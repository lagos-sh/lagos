//! Token-signing keys, fetched and cached.
//!
//! Verification needs only an issuer's *public* keys, so the gateway holds no
//! secret for any identity provider it trusts — which is what lets one gateway
//! verify tokens for several providers at once.
//!
//! Two wire formats are handled, because the one Google publishes is not the
//! standard one:
//!
//! - [`KeyFormat::Jwks`] — RFC 7517, `{"keys":[{"kty":"RSA","kid":…}]}`. What
//!   every OIDC provider serves at its `jwks_uri`.
//! - [`KeyFormat::X509Pem`] — `{"<kid>":"-----BEGIN CERTIFICATE-----…"}`, which
//!   is what Google's securetoken endpoint returns for Firebase.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use jsonwebtoken::DecodingKey;
use tokio::sync::{RwLock, broadcast};

use super::AuthError;

/// Cap on a fetched key set. Real ones are a few kilobytes — Google's Firebase
/// certificate map is under 4 KiB and a large OIDC JWKS a few tens — so this is
/// two orders of magnitude of headroom and still bounds what a misbehaving or
/// compromised key endpoint can make the gateway allocate.
const MAX_KEY_SET_BYTES: u64 = 1024 * 1024;

/// Longest a fetched key set is trusted, whatever `max-age` the endpoint sends.
///
/// Rotation is picked up only by expiry (an unknown `kid` on a fresh cache is
/// refused, not refetched), so an endpoint advertising a year would refuse
/// every token signed by a new key for that year and keep a revoked key valid
/// as long. Real endpoints send hours. A configured minimum above this wins.
const MAX_KEY_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// How long to cache a key set: the endpoint's `max-age`, at least `min_ttl`,
/// and at most [`MAX_KEY_TTL`] unless the operator's minimum is higher.
fn key_set_ttl(max_age: Option<Duration>, min_ttl: Duration) -> Duration {
    max_age
        .unwrap_or(min_ttl)
        .min(MAX_KEY_TTL.max(min_ttl))
        .max(min_ttl)
}

struct Cached {
    keys: HashMap<String, DecodingKey>,
    expires_at: Instant,
}

impl Cached {
    fn is_fresh(&self) -> bool {
        self.expires_at > Instant::now()
    }

    /// A miss on a *fresh* cache is a bad `kid`, not a reason to refetch.
    /// Google rotation is handled by expiry, not by every unknown kid.
    fn key(&self, kid: &str) -> Result<DecodingKey, AuthError> {
        self.keys.get(kid).cloned().ok_or_else(|| {
            AuthError::Invalid(format!("unknown signing key `{}`", super::untrusted(kid)))
        })
    }
}

/// How an issuer publishes its signing keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    /// RFC 7517 JSON Web Key Set — what an OIDC `jwks_uri` serves.
    Jwks,
    /// A map of key id to PEM-encoded X.509 certificate, as Google publishes
    /// for Firebase.
    X509Pem,
}

// A cancelled fetch must release its broadcast sender as well as its future.
// Waiters receive a bounded failure, and the next request may lead a refresh.
type RefreshSlot = Mutex<Option<broadcast::Sender<Result<(), String>>>>;
struct RefreshLeader<'a>(Option<&'a RefreshSlot>);
impl Drop for RefreshLeader<'_> {
    fn drop(&mut self) {
        let Some(slot) = self.0.take() else {
            return;
        };
        if let Some(tx) = slot.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = tx.send(Err("certificate refresh interrupted".into()));
        }
    }
}

pub struct CertCache {
    client: reqwest::Client,
    url: String,
    format: KeyFormat,
    min_ttl: Duration,
    stale_if_error: Duration,
    inner: RwLock<Option<Cached>>,
    /// Coordinates a single in-flight refresh. The mutex is never held across
    /// the HTTP call — it only publishes or subscribes to the broadcast.
    inflight: Mutex<Option<broadcast::Sender<Result<(), String>>>>,
}

impl CertCache {
    pub fn new(url: String, min_ttl: Duration) -> Self {
        Self::with_format(url, min_ttl, KeyFormat::X509Pem)
    }

    pub fn with_format(url: String, min_ttl: Duration, format: KeyFormat) -> Self {
        // The only builder option set here is a timeout, so this can fail
        // only if the TLS backend itself will not initialize — in which case
        // the gateway cannot verify a single token and must not start.
        #[allow(clippy::expect_used)]
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("rustls backend initializes, or no token can ever be verified");
        Self {
            client,
            url,
            format,
            min_ttl,
            stale_if_error: Duration::ZERO,
            inner: RwLock::new(None),
            inflight: Mutex::new(None),
        }
    }

    /// Opt in to bounded stale keys after a failed refresh. The bound is
    /// measured from the original expiry and never extended by failures.
    pub fn with_stale_if_error(mut self, maximum: Duration) -> Self {
        self.stale_if_error = maximum;
        self
    }

    /// Return the decoding key for `kid`.
    ///
    /// A populated, unexpired cache is authoritative: an unknown `kid` is
    /// rejected without another round trip. The set is refreshed only when it
    /// is empty or expired, and concurrent refreshers share one fetch.
    pub async fn key_for(&self, kid: &str) -> Result<DecodingKey, AuthError> {
        if let Some(cached) = self.inner.read().await.as_ref()
            && cached.is_fresh()
        {
            return cached.key(kid);
        }

        if let Err(error) = self.refresh().await {
            if !self.stale_if_error.is_zero()
                && let Some(cached) = self.inner.read().await.as_ref()
            {
                // Unknown kids are never resolved with stale material.
                if !cached.keys.contains_key(kid) {
                    return cached.key(kid);
                }
                if cached
                    .expires_at
                    .checked_add(self.stale_if_error)
                    .is_some_and(|until| Instant::now() < until)
                {
                    if let Some(metrics) = crate::metrics::metrics() {
                        metrics.record_jwks("stale_used");
                    }
                    return cached.key(kid);
                }
                if let Some(metrics) = crate::metrics::metrics() {
                    metrics.record_jwks("stale_exhausted");
                }
            }
            return Err(error);
        }

        let guard = self.inner.read().await;
        let cached = guard.as_ref().ok_or_else(|| {
            AuthError::Unavailable("certificate cache empty after refresh".into())
        })?;
        cached.key(kid)
    }

    async fn refresh(&self) -> Result<(), AuthError> {
        if self
            .inner
            .read()
            .await
            .as_ref()
            .is_some_and(Cached::is_fresh)
        {
            return Ok(());
        }

        let waiter = {
            let mut slot = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(tx) = slot.as_ref() {
                Some(tx.subscribe())
            } else {
                let (tx, _rx) = broadcast::channel(1);
                *slot = Some(tx);
                None
            }
        };

        if let Some(mut rx) = waiter {
            return match rx.recv().await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(msg)) => Err(AuthError::Unavailable(msg)),
                Err(_) => {
                    // Leader vanished; try to become the next one.
                    Box::pin(self.refresh()).await
                }
            };
        }

        let mut leader = RefreshLeader(Some(&self.inflight));
        let outcome = match self.fetch().await {
            Ok((keys, ttl)) => {
                *self.inner.write().await = Some(Cached {
                    keys,
                    // `Instant + Duration` panics on overflow, and this runs on the
                    // token-verification path. A cache entry that cannot be
                    // dated is simply treated as already expired.
                    expires_at: Instant::now().checked_add(ttl).unwrap_or_else(Instant::now),
                });
                Ok(())
            }
            Err(e) => {
                if let Some(metrics) = crate::metrics::metrics() {
                    metrics.record_jwks("refresh_failed");
                }
                Err(e)
            }
        };

        let notify = {
            let mut slot = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            // Disarm before publishing an empty slot: a later refresh may
            // install its sender as soon as this mutex is released.
            leader.0 = None;
            slot.take()
        };
        if let Some(tx) = notify {
            let _ = tx.send(match &outcome {
                Ok(()) => Ok(()),
                Err(e) => Err(e.to_string()),
            });
        }
        outcome
    }

    async fn fetch(&self) -> Result<(HashMap<String, DecodingKey>, Duration), AuthError> {
        let resp = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| AuthError::Unavailable(format!("certificate fetch failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(AuthError::Unavailable(format!(
                "certificate endpoint returned {}",
                resp.status()
            )));
        }

        // Declared oversize is refused before a byte of it is read.
        if let Some(len) = resp.content_length()
            && len > MAX_KEY_SET_BYTES
        {
            return Err(AuthError::Unavailable(format!(
                "key set declares {len} bytes, over the {MAX_KEY_SET_BYTES} byte cap"
            )));
        }

        let ttl = key_set_ttl(max_age(resp.headers()), self.min_ttl);

        // Read in chunks rather than `bytes()`, which buffers whatever arrives.
        // The endpoint is operator configuration, not caller input, but it is
        // still a third party over the network: a compromised or simply broken
        // key server must not be able to exhaust the gateway's memory, and a
        // chunked response can carry far more than its `Content-Length` said.
        let mut raw: Vec<u8> = Vec::new();
        let mut resp = resp;
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| AuthError::Unavailable(format!("key set could not be read: {e}")))?
        {
            if raw.len().saturating_add(chunk.len()) as u64 > MAX_KEY_SET_BYTES {
                return Err(AuthError::Unavailable(format!(
                    "key set exceeded the {MAX_KEY_SET_BYTES} byte cap"
                )));
            }
            raw.extend_from_slice(&chunk);
        }

        let keys = match self.format {
            KeyFormat::X509Pem => parse_x509_map(&raw)?,
            KeyFormat::Jwks => parse_jwks(&raw)?,
        };
        if keys.is_empty() {
            return Err(AuthError::Unavailable(
                "no usable signing certificates".into(),
            ));
        }
        Ok((keys, ttl))
    }
}

/// `{"<kid>": "<PEM certificate>"}` — Google's shape.
fn parse_x509_map(body: &[u8]) -> Result<HashMap<String, DecodingKey>, AuthError> {
    let map: HashMap<String, String> = serde_json::from_slice(body)
        .map_err(|e| AuthError::Unavailable(format!("certificate body was not JSON: {e}")))?;

    let mut keys = HashMap::with_capacity(map.len());
    for (kid, pem) in map {
        match decoding_key_from_x509_pem(&pem) {
            Ok(key) => {
                keys.insert(kid, key);
            }
            // One malformed certificate must not blank the whole set — the
            // others are still valid and tokens signed with them still verify.
            Err(e) => {
                tracing::warn!(kid = %kid, error = %e, "skipping unparsable signing certificate")
            }
        }
    }
    Ok(keys)
}

/// One key in an RFC 7517 key set. Unknown fields are ignored: providers add
/// their own, and a strict reader would reject perfectly usable key sets.
#[derive(serde::Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    r#use: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

#[derive(serde::Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// RFC 7517 JSON Web Key Set.
fn parse_jwks(body: &[u8]) -> Result<HashMap<String, DecodingKey>, AuthError> {
    let set: JwkSet = serde_json::from_slice(body)
        .map_err(|e| AuthError::Unavailable(format!("JWKS body was not a key set: {e}")))?;

    let mut keys = HashMap::with_capacity(set.keys.len());
    for jwk in set.keys {
        // `use: enc` keys are for encryption, not signatures. Accepting one
        // would mean verifying a signature against a key never meant for it.
        if jwk.r#use.as_deref().is_some_and(|u| u != "sig") {
            continue;
        }
        let Some(kid) = jwk.kid.clone() else {
            // Without a kid a token cannot select this key, so it is unusable.
            tracing::warn!(kty = %jwk.kty, "skipping JWKS entry with no `kid`");
            continue;
        };

        let built = match jwk.kty.as_str() {
            "RSA" => match (&jwk.n, &jwk.e) {
                (Some(n), Some(e)) => DecodingKey::from_rsa_components(n, e)
                    .map_err(|e| format!("bad RSA components: {e}")),
                _ => Err("RSA key is missing `n` or `e`".to_string()),
            },
            "EC" => match (&jwk.x, &jwk.y) {
                (Some(x), Some(y)) => DecodingKey::from_ec_components(x, y)
                    .map_err(|e| format!("bad EC components: {e}")),
                _ => Err("EC key is missing `x` or `y`".to_string()),
            },
            "OKP" => match &jwk.x {
                Some(x) => DecodingKey::from_ed_components(x)
                    .map_err(|e| format!("bad Ed components: {e}")),
                None => Err("OKP key is missing `x`".to_string()),
            },
            other => Err(format!("unsupported key type `{other}`")),
        };

        match built {
            Ok(key) => {
                keys.insert(kid, key);
            }
            Err(e) => tracing::warn!(kid = %kid, error = %e, "skipping unusable JWKS key"),
        }
    }
    Ok(keys)
}

fn max_age(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let cc = headers.get(reqwest::header::CACHE_CONTROL)?.to_str().ok()?;
    cc.split(',')
        .filter_map(|part| part.trim().strip_prefix("max-age="))
        .find_map(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

/// Extract the RSA public key from a PEM-encoded X.509 certificate.
///
/// `jsonwebtoken` cannot read a certificate directly — it wants the bare public
/// key — so we parse the certificate and hand over its SubjectPublicKeyInfo,
/// which for RSA is a DER-encoded PKCS#1 `RSAPublicKey`.
pub fn decoding_key_from_x509_pem(pem: &str) -> Result<DecodingKey, String> {
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .map_err(|e| format!("not a valid PEM block: {e}"))?;
    let cert = parsed
        .parse_x509()
        .map_err(|e| format!("not a valid X.509 certificate: {e}"))?;
    let spki = cert.public_key();
    Ok(DecodingKey::from_rsa_der(&spki.subject_public_key.data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_advertised_key_lifetime_is_capped_but_the_operator_minimum_wins() {
        let min = Duration::from_secs(60);
        let hour = Duration::from_secs(3600);
        assert_eq!(key_set_ttl(Some(hour), min), hour);
        assert_eq!(key_set_ttl(None, min), min);
        assert_eq!(key_set_ttl(Some(Duration::from_secs(1)), min), min);
        assert_eq!(
            key_set_ttl(Some(Duration::from_secs(365 * 86_400)), min),
            MAX_KEY_TTL
        );
        // `max-age=18446744073709551615` used to overflow the expiry and make
        // every verification refetch.
        let huge = key_set_ttl(Some(Duration::from_secs(u64::MAX)), min);
        assert_eq!(huge, MAX_KEY_TTL);
        assert!(Instant::now().checked_add(huge).is_some());
        let long_min = Duration::from_secs(2 * 86_400);
        assert_eq!(
            key_set_ttl(Some(Duration::from_secs(u64::MAX)), long_min),
            long_min
        );
    }
    use reqwest::header::{CACHE_CONTROL, HeaderMap, HeaderValue};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// A self-signed RSA cert used only to populate the cache in tests.
    /// The key material is not a secret; nothing verifies a signature against it here.
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDFTCCAf2gAwIBAgIURND4mWok1RIydh7wOJ96sz8j2GQwDQYJKoZIhvcNAQEL\n\
BQAwGjEYMBYGA1UEAwwPbGFnb3Mtandrcy10ZXN0MB4XDTI2MDkxMTE1MjA0NVoX\n\
DTM2MDkwODE1MjA0NVowGjEYMBYGA1UEAwwPbGFnb3Mtandrcy10ZXN0MIIBIjAN\n\
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApuBb8FMu3uLu3+Y8NF/6+uo8WGW2\n\
ygmkq+R9P0EedaULq/D7cnQKGWdHKc1nZ9Qw3sU75HC7PR5y/FCU3ew4G/5vJniP\n\
OU/IqAlpR72TTsIs5UtXy5zSL08ofAEuYJ+h+VqBXD6geeRuEuV0ndbN52uEfGpU\n\
gSFMMXObfREWKk/TH5HCVIt3tP8UZFFyStSxeXpYqq1TNO7K9Or/sBGlYK8fxtRA\n\
lfUe92YB1uXLcspGCrUf+6EzIc2UhsOO4gmM/W0FWMpuZYX1pdH4BsAIYyx8dCxB\n\
Uy4AD6sg2GkeaxbgXiP1PmpX6Y1T3/X2HxTq2RiApUeaaSmBtOQKWiOVbwIDAQAB\n\
o1MwUTAdBgNVHQ4EFgQUWIdc66vhZIcVWe14tqInOeT8Yi8wHwYDVR0jBBgwFoAU\n\
WIdc66vhZIcVWe14tqInOeT8Yi8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B\n\
AQsFAAOCAQEASRx41znBQUww966t5bYfcmT7X3Ac4fj4w+jKjGDApATxZOFrlyEE\n\
Gwvkt2jfWRbMIyfeP7QOJyPCJ2ppAHooec7cuNRvF8hGw2zurxbXZHMOqZk+k3Ji\n\
/QyWQrBuytyLRa6wo9ECP76wHgHE0VLw0tqXAFQWTsv9ivpw0ukVhBHqxE8K5ad9\n\
nafMyFxFg5NrV5+UDfckVfMrBkeSpWstv1guPMcFr+K5MDa6qYTR6cmVc87cnWxR\n\
DkoN4xwPYHoIO/r6pOIAE5+pO7WqFOfh3/biiXh4VHH1YGl0VRzyn0HN/EzjnswW\n\
mDzE1ub38vZH0fBp4LxDL3zeViZv7DyeAw==\n\
-----END CERTIFICATE-----\n";

    fn spawn_cert_server(max_age: u64) -> (String, Arc<AtomicUsize>) {
        spawn_cert_server_with_delay(max_age, Duration::ZERO)
    }

    fn spawn_cert_server_with_delay(max_age: u64, delay: Duration) -> (String, Arc<AtomicUsize>) {
        spawn_controlled_cert_server(max_age, delay, Arc::new(AtomicUsize::new(0)))
    }

    fn spawn_controlled_cert_server(
        max_age: u64,
        delay: Duration,
        state: Arc<AtomicUsize>,
    ) -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test cert server");
        let addr = listener.local_addr().expect("local_addr");
        let hits_clone = hits.clone();
        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(mut stream) = incoming else { continue };
                let first = hits_clone.fetch_add(1, Ordering::SeqCst) == 0;
                let state = state.load(Ordering::SeqCst);
                if first || state == 2 {
                    std::thread::sleep(delay);
                }
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                if state == 2 {
                    let _ = stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    continue;
                }
                let kid = if state == 1 {
                    "rotated-kid"
                } else {
                    "known-kid"
                };
                let body = serde_json::json!({ kid: TEST_CERT_PEM }).to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: max-age={max_age}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        (format!("http://{addr}/"), hits)
    }

    #[tokio::test]
    async fn rotation_then_outage_cannot_resurrect_a_removed_key() {
        let state = Arc::new(AtomicUsize::new(0));
        let (url, _) = spawn_controlled_cert_server(3600, Duration::ZERO, state.clone());
        let cache = CertCache::new(url, Duration::from_secs(1))
            .with_stale_if_error(Duration::from_secs(60));
        cache.key_for("known-kid").await.unwrap();
        state.store(1, Ordering::SeqCst);
        cache.inner.write().await.as_mut().unwrap().expires_at = Instant::now();
        cache.key_for("rotated-kid").await.unwrap();
        state.store(2, Ordering::SeqCst);
        cache.inner.write().await.as_mut().unwrap().expires_at = Instant::now();
        assert!(matches!(
            cache.key_for("known-kid").await,
            Err(AuthError::Invalid(_))
        ));
        assert!(cache.key_for("rotated-kid").await.is_ok());
    }

    #[tokio::test]
    async fn concurrent_expired_lookups_share_failed_refresh_and_can_retry() {
        let state = Arc::new(AtomicUsize::new(0));
        let (url, hits) =
            spawn_controlled_cert_server(3600, Duration::from_millis(100), state.clone());
        let cache = Arc::new(
            CertCache::new(url, Duration::from_secs(1))
                .with_stale_if_error(Duration::from_secs(60)),
        );
        cache.key_for("known-kid").await.unwrap();
        cache.inner.write().await.as_mut().unwrap().expires_at = Instant::now();
        state.store(2, Ordering::SeqCst);
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let cache = cache.clone();
            tasks.push(tokio::spawn(
                async move { cache.key_for("known-kid").await },
            ));
        }
        for task in tasks {
            assert!(task.await.unwrap().is_ok());
        }
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        state.store(1, Ordering::SeqCst);
        assert!(cache.key_for("rotated-kid").await.is_ok());
    }

    #[tokio::test]
    async fn cancelled_refresh_leader_does_not_strand_waiters() {
        let (url, hits) = spawn_cert_server_with_delay(3600, Duration::from_millis(150));
        let cache = Arc::new(CertCache::new(url, Duration::from_secs(1)));
        let first = tokio::spawn({
            let cache = cache.clone();
            async move { cache.key_for("known-kid").await }
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while hits.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        let waiter = tokio::spawn({
            let cache = cache.clone();
            async move { cache.key_for("known-kid").await }
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        first.abort();
        let _ = first.await;
        // A waiter either receives cancellation or becomes the next leader.
        let _ = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .unwrap()
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), cache.key_for("known-kid"))
                .await
                .unwrap()
                .is_ok()
        );
    }

    #[tokio::test]
    async fn stale_keys_are_bounded_and_recovery_replaces_them() {
        let (url, _) = spawn_cert_server(3600);
        let mut cache = CertCache::new(url.clone(), Duration::from_secs(1))
            .with_stale_if_error(Duration::from_secs(60));
        cache.key_for("known-kid").await.unwrap();
        cache.inner.write().await.as_mut().unwrap().expires_at =
            Instant::now() - Duration::from_secs(1);
        cache.url = "http://127.0.0.1:1/unavailable".into();
        assert!(cache.key_for("known-kid").await.is_ok());
        assert!(matches!(
            cache.key_for("unknown").await,
            Err(AuthError::Invalid(_))
        ));
        cache.inner.write().await.as_mut().unwrap().expires_at =
            Instant::now() - Duration::from_secs(61);
        assert!(cache.key_for("known-kid").await.is_err());
        cache.url = url;
        assert!(cache.key_for("known-kid").await.is_ok());
        cache.url = "http://127.0.0.1:1/unavailable".into();
        cache.inner.write().await.as_mut().unwrap().expires_at =
            Instant::now() - Duration::from_secs(1);
        cache.stale_if_error = Duration::ZERO;
        assert!(
            cache.key_for("known-kid").await.is_err(),
            "default stays fail closed"
        );
        let cold = CertCache::new(cache.url.clone(), Duration::from_secs(1))
            .with_stale_if_error(Duration::from_secs(60));
        assert!(cold.key_for("known-kid").await.is_err());
    }

    #[test]
    fn parses_max_age_from_cache_control() {
        let mut h = HeaderMap::new();
        h.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=19986, must-revalidate, no-transform"),
        );
        assert_eq!(max_age(&h), Some(Duration::from_secs(19986)));
    }

    #[test]
    fn missing_cache_control_yields_none() {
        assert_eq!(max_age(&HeaderMap::new()), None);
    }

    #[test]
    fn rejects_garbage_certificates() {
        assert!(decoding_key_from_x509_pem("not a pem").is_err());
        assert!(
            decoding_key_from_x509_pem(
                "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n"
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn a_fresh_cache_rejects_an_unknown_kid_without_refetching() {
        let (url, hits) = spawn_cert_server(3600);
        let cache = CertCache::new(url, Duration::from_secs(300));

        cache
            .key_for("known-kid")
            .await
            .expect("known kid must load from a cold cache");
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        match cache.key_for("bogus-kid").await {
            Err(AuthError::Invalid(_)) => {}
            Ok(_) => panic!("unknown kid on a fresh cache must fail closed"),
            Err(other) => panic!("expected Invalid, got {other:?}"),
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "a bogus kid must not trigger another certificate fetch"
        );
    }

    #[tokio::test]
    async fn an_expired_cache_refetches_once_then_rejects_an_unknown_kid() {
        let (url, hits) = spawn_cert_server(0);
        let cache = CertCache::new(url, Duration::from_millis(20));

        cache.key_for("known-kid").await.expect("cold cache fetch");
        tokio::time::sleep(Duration::from_millis(40)).await;

        match cache.key_for("bogus-kid").await {
            Err(AuthError::Invalid(_)) => {}
            Ok(_) => panic!("unknown kid after expiry still fails"),
            Err(other) => panic!("expected Invalid, got {other:?}"),
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "expiry is a legitimate reason to refetch once"
        );
    }

    #[tokio::test]
    async fn concurrent_lookups_on_a_cold_cache_share_one_fetch() {
        let (url, hits) = spawn_cert_server(3600);
        let cache = Arc::new(CertCache::new(url, Duration::from_secs(300)));

        let mut tasks = Vec::new();
        for _ in 0..16 {
            let cache = cache.clone();
            tasks.push(tokio::spawn(
                async move { cache.key_for("known-kid").await },
            ));
        }
        for task in tasks {
            task.await
                .expect("task join")
                .expect("known kid must resolve");
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "concurrent cold misses must single-flight"
        );
    }
}
