//! Cluster-wide counting: the RESP half.
//!
//! Behind the `shared-limits` feature, so the default binary carries neither
//! the dependency nor a connection.
//!
//! # Why these commands
//!
//! `HSETNX`, `EXPIRE` and `HVALS` for reconciliation, `RLCHECK` for the exact
//! mode. Nothing else, and in particular **no `EVAL`**: Recached implements no
//! Lua at all, so the usual trick of shipping a sliding-window script would not
//! run against the backend this is built for. Keeping to the portable subset is
//! also what lets one code path serve Recached, Redis and Valkey identically.
//!
//! # Connecting cannot be a boot dependency
//!
//! The connection is lazy. A gateway whose cache is down must still start and
//! still serve — degraded to per-process counting — because the alternative is
//! that a cache outage becomes a total outage, which is the failure this
//! project's roadmap rules out explicitly. The one exception is
//! [`crate::config::LimitMode::Exact`], which cannot be honoured at all without
//! the backend and is therefore verified at startup instead.
//!
//! # Why the backend owns a runtime
//!
//! Pingora creates **one Tokio runtime per service** — the public proxy, the
//! internal proxy and each background service all get their own. A Tokio I/O
//! resource belongs to the runtime whose driver registered it, so a connection
//! opened on the sync task's runtime cannot be used from a proxy worker, which
//! is exactly what `mode: exact` would do on every request.
//!
//! Rather than keep a connection per runtime and reason about which one is
//! current, the backend owns one small runtime and every command is spawned
//! onto it. Callers await an ordinary `JoinHandle`, which works from any
//! runtime, and the connection is multiplexed across all of them. The cost is
//! one thread and a task handoff per call — microseconds against a network
//! round trip, and nothing at all in the default mode, where only the sync task
//! ever calls in.

use std::time::Duration;

use super::Decision;
use super::shared::{Backend, BackendError, Publish, Totals};

/// Only the two `HVALS` replies are retained for each key.
const REPLIES_PER_KEY: usize = 2;

/// Which server answered, from `INFO server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Vendor {
    /// Recached, which has `RLCHECK` and so can serve the exact mode.
    Recached,
    /// Something else speaking RESP. Reconciliation works; the exact mode does
    /// not, because `RLCHECK` has no counterpart and cannot be emulated without
    /// the `EVAL` that Recached does not implement either.
    Other(String),
}

impl std::fmt::Display for Vendor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Recached => f.write_str("Recached"),
            Self::Other(name) if name.is_empty() => f.write_str("an unidentified RESP server"),
            Self::Other(name) => f.write_str(name),
        }
    }
}

/// Read a vendor out of an `INFO` payload.
///
/// `recached_version` is the signal, the way KeyDB and Dragonfly also ship their
/// own version alongside a `redis_version` they report for compatibility —
/// Recached reports `redis_version:6.2.0` precisely so clients do not disable
/// features it has, which means `redis_version` says nothing about who
/// answered.
pub fn vendor_from_info(info: &str) -> Vendor {
    let mut name = String::new();
    for line in info.lines() {
        let line = line.trim();
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        match field {
            "recached_version" => return Vendor::Recached,
            "server_name" if value.eq_ignore_ascii_case("recached") => return Vendor::Recached,
            "server_name" => name = value.to_string(),
            _ => {}
        }
    }
    Vendor::Other(name)
}

/// A RESP-backed shared counter store.
pub struct RespBackend {
    /// Drives every command. See the module docs: this exists because a
    /// connection cannot be shared across Pingora's per-service runtimes.
    ///
    /// `Option` only so that [`Drop`] can take it; it is `Some` for the whole
    /// useful life of the backend. Commands are spawned through `handle`, so
    /// the hot path never unwraps it.
    runtime: Option<tokio::runtime::Runtime>,
    handle: tokio::runtime::Handle,
    /// Cloned per call: the manager is an `Arc` inside and reconnects on its
    /// own, so a clone is cheap and there is no pool to size or lock to hold.
    conn: redis::aio::ConnectionManager,
    timeout: Duration,
    /// For diagnostics only, and redacted — see
    /// [`super::shared::redact_url`].
    display_url: String,
}

impl Drop for RespBackend {
    /// Detach the runtime rather than dropping it in place.
    ///
    /// Dropping a Tokio runtime blocks until its workers stop, which **panics**
    /// if it happens inside an async context — and it will: this backend is
    /// reachable from a route table, so the last reference is released whenever
    /// a reload swaps that table out, on a Pingora worker, mid-request.
    /// `shutdown_background` hands the threads off instead and returns
    /// immediately.
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl std::fmt::Debug for RespBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RespBackend")
            .field("url", &self.display_url)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl RespBackend {
    /// Build a backend without waiting for the cache to answer.
    ///
    /// `cfg.url` is normalized from whichever alias was configured; the error
    /// never echoes the URL, which routinely carries a password.
    pub fn connect(cfg: &crate::config::SharedCountersConfig) -> Result<Self, String> {
        let url = super::shared::normalize_url(&cfg.url)?;
        let display_url = super::shared::redact_url(&cfg.url);

        let client = redis::Client::open(url)
            .map_err(|e| format!("shared_counters.url could not be parsed: {}", e.category()))?;

        let manager_cfg = redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Some(cfg.timeout))
            .set_response_timeout(Some(cfg.timeout));

        // Multi-threaded with one worker, not `new_current_thread`: a
        // current-thread runtime is only driven while something calls
        // `block_on`, so tasks spawned onto it from elsewhere would never run.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("lagos-shared-limits")
            .enable_all()
            .build()
            .map_err(|e| format!("shared counter runtime could not be started: {e}"))?;

        // Built inside that runtime so its reactor is the one registered.
        // Constructing a connection manager requires a reactor even though it
        // connects lazily, which is why this cannot be done at plain startup.
        let conn = {
            let _guard = runtime.enter();
            // Lazy on purpose: see the module docs. A cache that is down must
            // not stop the gateway from starting.
            redis::aio::ConnectionManager::new_lazy_with_config(client, manager_cfg)
                .map_err(|e| format!("shared counter connection could not be set up: {e}"))?
        };

        Ok(Self {
            handle: runtime.handle().clone(),
            runtime: Some(runtime),
            conn,
            timeout: cfg.timeout,
            display_url,
        })
    }

    /// The redacted URL, for startup logging.
    pub fn url(&self) -> &str {
        &self.display_url
    }

    /// Ask the backend who it is. See [`Backend::probe`].
    async fn vendor(&self) -> Result<Vendor, BackendError> {
        let info: String = self
            .on_backend(|mut conn| async move {
                redis::cmd("INFO")
                    .arg("server")
                    .query_async(&mut conn)
                    .await
            })
            .await?;
        Ok(vendor_from_info(&info))
    }

    /// Run one command on the backend's runtime, under the configured budget.
    ///
    /// The closure receives its own clone of the connection so the future can be
    /// `'static` and therefore spawnable; the timeout runs on that runtime too,
    /// where its timer is actually driven.
    async fn on_backend<T, F, Fut>(&self, f: F) -> Result<T, BackendError>
    where
        T: Send + 'static,
        F: FnOnce(redis::aio::ConnectionManager) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = redis::RedisResult<T>> + Send,
    {
        let conn = self.conn.clone();
        let budget = self.timeout;
        let task = self
            .handle
            .spawn(async move { tokio::time::timeout(budget, f(conn)).await });

        match task.await {
            Ok(Ok(Ok(value))) => Ok(value),
            // `category()` rather than the whole error: a redis error can carry
            // the command it failed on, and these commands' arguments include a
            // rate-limit key -- an address or a token subject.
            Ok(Ok(Err(e))) => Err(BackendError::Unavailable(e.category().to_string())),
            Ok(Err(_)) => Err(BackendError::Timeout(budget)),
            // The worker panicked or was cancelled. Reported as unavailable so
            // it degrades the same way a dead cache does rather than taking a
            // request with it.
            Err(e) => Err(BackendError::Unavailable(format!("worker failed: {e}"))),
        }
    }

    /// Separate hash counters from the original scalar counter format.
    fn bucket_key(key: &str, bucket: u64) -> String {
        format!("{key}:shared-v2:{bucket}")
    }

    /// How long a window's counter is kept.
    ///
    /// Two intervals, because the sliding estimate reads the previous window and
    /// nothing older contributes anything. Floored at two seconds so a
    /// sub-second interval -- which validation refuses for shared counters, but
    /// which arithmetic here should survive anyway -- cannot round down to a
    /// zero TTL, which in RESP means "no expiry" and would leak a key per
    /// window forever.
    fn ttl_secs(interval: Duration) -> u64 {
        let lifetime = interval.saturating_mul(2);
        lifetime
            .as_secs()
            .saturating_add(u64::from(lifetime.subsec_nanos() != 0))
            .max(2)
    }
}

#[async_trait::async_trait]
impl Backend for RespBackend {
    async fn reconcile(&self, batch: &[Publish]) -> Result<Vec<Totals>, BackendError> {
        if batch.is_empty() {
            return Ok(Vec::new());
        }

        let mut pipe = redis::Pipeline::new();
        for publish in batch {
            for (bucket, delta) in [
                (publish.bucket, publish.delta),
                (publish.bucket.saturating_sub(1), publish.delta_previous),
            ] {
                let key = Self::bucket_key(&publish.key, bucket);
                // Immutable contributions commute across replicas and retries.
                // If a reply is lost after the write, HSETNX recognizes the same
                // ID on retry instead of adding its delta a second time.
                if delta != 0 {
                    pipe.cmd("HSETNX")
                        .arg(&key)
                        .arg(publish.id.to_string())
                        .arg(delta)
                        .ignore();
                }
                pipe.cmd("EXPIRE")
                    .arg(&key)
                    .arg(Self::ttl_secs(publish.interval))
                    .ignore();
                pipe.cmd("HVALS").arg(&key);
            }
        }

        let replies: Vec<Vec<u64>> = self
            .on_backend(move |mut conn| async move { pipe.query_async(&mut conn).await })
            .await?;
        if replies.len() != batch.len().saturating_mul(REPLIES_PER_KEY) {
            return Err(BackendError::Protocol(format!(
                "expected {} replies for {} keys, got {}",
                batch.len().saturating_mul(REPLIES_PER_KEY),
                batch.len(),
                replies.len()
            )));
        }
        let (chunks, _) = replies.as_chunks::<REPLIES_PER_KEY>();
        Ok(batch
            .iter()
            .zip(chunks)
            .map(|(publish, [current, previous])| Totals {
                current: current.iter().fold(0_u64, |sum, n| sum.saturating_add(*n)),
                previous: if publish.bucket == 0 {
                    0
                } else {
                    previous.iter().fold(0_u64, |sum, n| sum.saturating_add(*n))
                },
            })
            .collect())
    }

    async fn check_exact(
        &self,
        key: &str,
        limit: u64,
        interval: Duration,
    ) -> Result<Decision, BackendError> {
        // `RLCHECK key limit window` -> [allowed, remaining, retry_after_ms].
        // Refuse unsupported widths even for callers outside config validation.
        if interval.is_zero() || interval.subsec_nanos() != 0 {
            return Err(BackendError::Protocol(
                "RLCHECK requires an interval in whole seconds".into(),
            ));
        }
        let window = interval.as_secs();
        let key = key.to_string();
        let reply: Vec<i64> = self
            .on_backend(move |mut conn| async move {
                redis::cmd("RLCHECK")
                    .arg(key)
                    .arg(limit)
                    .arg(window)
                    .query_async(&mut conn)
                    .await
            })
            .await?;

        let (Some(allowed), Some(remaining), Some(retry_ms)) =
            (reply.first(), reply.get(1), reply.get(2))
        else {
            return Err(BackendError::Protocol(format!(
                "RLCHECK returned {} values, expected 3",
                reply.len()
            )));
        };

        if *allowed == 1 {
            return Ok(Decision::allow(
                limit,
                u64::try_from(*remaining).unwrap_or(0),
            ));
        }

        // Rounded up. A `Retry-After` shorter than the real wait sends a
        // well-behaved client back for a second 429, which reads to that client
        // as the gateway lying to it.
        let wait = u64::try_from(*retry_ms).unwrap_or(0).div_ceil(1000);
        Ok(Decision::refuse(limit, Duration::from_secs(wait)))
    }

    async fn probe(&self) -> Result<(String, bool), BackendError> {
        let vendor = self.vendor().await?;
        // Only Recached has `RLCHECK`, and it cannot be emulated elsewhere
        // without the `EVAL` Recached itself does not implement.
        let exact = vendor == Vendor::Recached;
        Ok((vendor.to_string(), exact))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recached_is_recognised_by_its_own_version_field() {
        // The field Recached ships alongside the `redis_version` it reports for
        // client compatibility.
        assert_eq!(
            vendor_from_info("redis_version:6.2.0\r\nrecached_version:0.2.3\r\n"),
            Vendor::Recached
        );
        assert_eq!(
            vendor_from_info("server_name:recached\r\nredis_version:7.2.0\r\n"),
            Vendor::Recached
        );
    }

    #[test]
    fn another_resp_server_is_not_mistaken_for_recached() {
        // It would be, if `redis_version` were the signal -- Recached reports
        // 6.2.0 there on purpose.
        assert_eq!(
            vendor_from_info("redis_version:7.2.4\r\nredis_mode:standalone\r\n"),
            Vendor::Other(String::new())
        );
        assert_eq!(
            vendor_from_info("server_name:valkey\r\nvalkey_version:8.0.0\r\n"),
            Vendor::Other("valkey".into())
        );
        assert_eq!(vendor_from_info(""), Vendor::Other(String::new()));
    }

    /// Settings pointed at a live server, or `None` to skip.
    ///
    /// Gated on an environment variable rather than assuming a server: these
    /// are the only tests that prove the wire format is right, so they must be
    /// runnable, but a unit test suite that needs a running cache is a suite
    /// people stop running.
    ///
    /// ```bash
    /// LAGOS_TEST_RESP_URL=recached://127.0.0.1:6379 cargo test --features shared-limits
    /// ```
    fn live_config() -> Option<crate::config::SharedCountersConfig> {
        let url = std::env::var("LAGOS_TEST_RESP_URL").ok()?;
        Some(crate::config::SharedCountersConfig {
            url,
            sync: Duration::from_secs(1),
            prefix: format!("lagos-test:{}:", std::process::id()),
            timeout: Duration::from_secs(2),
            max_keys_per_sync: 64,
        })
    }

    fn publish(key: &str, bucket: u64, delta: u64, own_current: u64, own_previous: u64) -> Publish {
        Publish {
            id: uuid::Uuid::new_v4(),
            source: uuid::Uuid::new_v4(),
            delta_previous: 0,
            key: key.to_string(),
            bucket,
            delta,
            own_current,
            own_previous,
            interval: Duration::from_secs(60),
        }
    }

    #[tokio::test]
    async fn reconciles_against_a_live_server() {
        let Some(cfg) = live_config() else {
            return;
        };
        let backend = RespBackend::connect(&cfg).expect("connect");
        let prefix = cfg.prefix;
        let bucket = 5;

        // First replica publishes 3.
        let batch = vec![publish(&format!("{prefix}k"), bucket, 3, 3, 0)];
        let totals = backend.reconcile(&batch).await.expect("reconcile");
        assert_eq!(
            totals,
            vec![Totals {
                current: 3,
                previous: 0
            }],
            "a first publish should read back exactly what it wrote"
        );

        // A second replica publishes 4 against the same key: the total is the
        // cluster's, which is the entire point.
        let batch = vec![publish(&format!("{prefix}k"), bucket, 4, 4, 0)];
        let totals = backend.reconcile(&batch).await.expect("reconcile");
        assert_eq!(
            totals.first().map(|t| t.current),
            Some(7),
            "the reply must be the cluster total, not this replica's delta"
        );

        // Previous-window reads have to line up with what the window before
        // actually holds, or the sliding weight is applied to nothing.
        let batch = vec![publish(&format!("{prefix}k"), bucket + 1, 1, 1, 7)];
        let totals = backend.reconcile(&batch).await.expect("reconcile");
        assert_eq!(
            totals.first().copied(),
            Some(Totals {
                current: 1,
                previous: 7
            }),
            "rolling forward must find the previous window's total"
        );
    }

    #[tokio::test]
    async fn retries_and_previous_window_deltas_are_idempotent_on_a_live_server() {
        let Some(cfg) = live_config() else {
            return;
        };
        let backend = RespBackend::connect(&cfg).expect("connect");
        let mut p = publish(&format!("{}retry", cfg.prefix), 21, 3, 3, 4);
        p.delta_previous = 4;
        let expected = vec![Totals {
            current: 3,
            previous: 4,
        }];
        assert_eq!(backend.reconcile(&[p.clone()]).await.unwrap(), expected);
        assert_eq!(backend.reconcile(&[p.clone()]).await.unwrap(), expected);
        let mut peer = publish(&p.key, 21, 2, 2, 1);
        peer.delta_previous = 1;
        assert_eq!(
            backend.reconcile(&[peer]).await.unwrap(),
            vec![Totals {
                current: 5,
                previous: 5
            }]
        );
        assert_eq!(
            backend.reconcile(&[p]).await.unwrap(),
            vec![Totals {
                current: 5,
                previous: 5
            }]
        );
    }

    #[tokio::test]
    async fn unsupported_exact_widths_are_refused_before_io() {
        let cfg = crate::config::SharedCountersConfig {
            url: "redis://127.0.0.1:1".into(),
            sync: Duration::from_secs(1),
            prefix: "t:".into(),
            timeout: Duration::from_millis(250),
            max_keys_per_sync: 64,
        };
        let backend = RespBackend::connect(&cfg).unwrap();
        for width in [Duration::ZERO, Duration::from_millis(1900)] {
            assert!(matches!(
                backend.check_exact("k", 10, width).await,
                Err(BackendError::Protocol(_))
            ));
        }
    }

    #[tokio::test]
    async fn a_multi_key_batch_stays_positionally_aligned() {
        // The failure mode worth a test of its own: one key's usage attributed
        // to another would refuse a caller who did nothing.
        let Some(cfg) = live_config() else {
            return;
        };
        let backend = RespBackend::connect(&cfg).expect("connect");
        let prefix = cfg.prefix;

        let batch: Vec<Publish> = (0..8)
            .map(|i| publish(&format!("{prefix}key-{i}"), 9, i, i, 0))
            .collect();
        let totals = backend.reconcile(&batch).await.expect("reconcile");

        assert_eq!(totals.len(), batch.len());
        for (i, total) in totals.iter().enumerate() {
            assert_eq!(
                total.current, i as u64,
                "key-{i} got another key's count back"
            );
        }
    }

    #[tokio::test]
    async fn every_window_counter_written_has_an_expiry() {
        // A leaked key per window per caller is a slow memory leak in somebody
        // else's database, which is the kind of bug that gets found by them.
        let Some(cfg) = live_config() else {
            return;
        };
        let backend = RespBackend::connect(&cfg).expect("connect");
        let prefix = cfg.prefix;
        let key = format!("{prefix}ttl");

        backend
            .reconcile(&[publish(&key, 11, 1, 1, 0)])
            .await
            .expect("reconcile");

        // Through `on_backend`, not the connection directly: using it from this
        // test's runtime would be the very cross-runtime mistake the backend
        // owns a runtime to avoid.
        let ttl_key = RespBackend::bucket_key(&key, 11);
        let ttl: i64 = backend
            .on_backend(move |mut conn| async move {
                redis::cmd("TTL").arg(ttl_key).query_async(&mut conn).await
            })
            .await
            .expect("TTL");
        // -1 is "exists, never expires"; -2 is "gone".
        assert!(ttl > 0 && ttl <= 120, "TTL was {ttl}");
    }

    #[tokio::test]
    async fn a_server_without_rlcheck_fails_the_probe_rather_than_lying() {
        // Redis and Valkey have no RLCHECK. `mode: exact` against one must be a
        // boot error, so the probe has to report it honestly.
        let Some(cfg) = live_config() else {
            return;
        };
        let backend = RespBackend::connect(&cfg).expect("connect");
        let (server, supports_exact) = backend.probe().await.expect("probe");

        if server == "Recached" {
            assert!(supports_exact, "Recached has RLCHECK");
            let decision = backend
                .check_exact(&format!("{}exact", cfg.prefix), 3, Duration::from_secs(60))
                .await
                .expect("RLCHECK");
            assert!(decision.allowed);
            assert_eq!(decision.limit, 3);
        } else {
            assert!(
                !supports_exact,
                "{server} has no RLCHECK, so it must not claim exactness"
            );
            // And the call itself must fail cleanly rather than parse garbage
            // into a decision that admits everything.
            assert!(
                backend
                    .check_exact(&format!("{}exact", cfg.prefix), 3, Duration::from_secs(60))
                    .await
                    .is_err(),
                "an unknown command must surface as an error"
            );
        }
    }

    #[tokio::test]
    async fn an_unreachable_server_times_out_instead_of_hanging() {
        // A port nothing listens on. The budget is the ceiling on how long a
        // request in `exact` mode can be held, so it has to actually apply.
        let cfg = crate::config::SharedCountersConfig {
            // 1 is reserved (tcpmux) and refuses connections quickly; either
            // shape -- refusal or timeout -- must come back as an error, and
            // must come back.
            url: "recached://127.0.0.1:1".into(),
            sync: Duration::from_secs(1),
            prefix: "lagos-test:".into(),
            timeout: Duration::from_millis(300),
            max_keys_per_sync: 64,
        };
        let backend = RespBackend::connect(&cfg).expect("a lazy connection cannot fail here");
        let started = std::time::Instant::now();
        let result = backend
            .reconcile(&[publish("lagos-test:x", 1, 1, 1, 0)])
            .await;
        assert!(
            result.is_err(),
            "an unreachable server must not look healthy"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the timeout budget did not apply; waited {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_counters_ttl_follows_its_own_routes_interval() {
        // The bug this guards: one backend serves every route, so a TTL derived
        // from anything but the key's own interval expires one route's window
        // on another route's schedule -- silently resetting a quota mid-window.
        let long = Publish {
            id: uuid::Uuid::new_v4(),
            source: uuid::Uuid::new_v4(),
            delta_previous: 0,
            key: "p:a".into(),
            bucket: 1,
            delta: 0,
            own_current: 0,
            own_previous: 0,
            interval: Duration::from_secs(3600),
        };
        let short = Publish {
            interval: Duration::from_secs(60),
            ..long.clone()
        };
        assert_eq!(RespBackend::ttl_secs(long.interval), 7200);
        assert_eq!(RespBackend::ttl_secs(short.interval), 120);
    }

    #[test]
    fn a_window_counter_always_gets_an_expiry() {
        // A zero TTL means "never expires" in RESP, which would leak one key
        // per window forever.
        assert_eq!(RespBackend::ttl_secs(Duration::from_secs(60)), 120);
        assert_eq!(RespBackend::ttl_secs(Duration::from_millis(500)), 2);
        assert_eq!(RespBackend::ttl_secs(Duration::ZERO), 2);
        assert_eq!(RespBackend::ttl_secs(Duration::from_millis(1900)), 4);
    }
}
