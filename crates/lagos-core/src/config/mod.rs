//! Declarative gateway configuration.
//!
//! One YAML document describes the whole gateway: where it listens, which
//! upstreams exist, how callers are authenticated, and every route that is
//! allowed through. Environment indirection is available anywhere via
//! [`interpolate`] rather than through a `*_env` field on each struct, so the
//! smallest working configuration needs no environment at all:
//!
//! ```yaml
//! upstreams:
//!   users: http://localhost:3000
//! routes:
//!   public:
//!     - prefix: /users
//!       upstream: users
//! ```
//!
//! Every struct here is `deny_unknown_fields`: a misspelled key is a startup
//! error naming the line, never a silently ignored policy.

pub mod interpolate;

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

pub use interpolate::{InterpolateError, Interpolated, interpolate};

use crate::routes::{RouteConfig, RouteGroups};

// ---------------------------------------------------------------- top level

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub timeouts: Timeouts,
    #[serde(default)]
    pub limits: Limits,
    /// Logical backend name to destination. The route table refers to these by
    /// name, so a URL change never touches a route.
    #[serde(default)]
    pub upstreams: BTreeMap<String, UpstreamConfig>,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub inject: InjectConfig,
    #[serde(default)]
    pub reject: RejectConfig,
    #[serde(default)]
    pub forward: ForwardConfig,
    #[serde(default)]
    pub identity: IdentityConfig,
    #[serde(default)]
    pub routes: RoutesConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
    /// Cross-origin policy, applied to every route.
    #[serde(default)]
    pub cors: Option<CorsConfig>,
    /// Response cache. Configures the store; routes opt in individually.
    #[serde(default)]
    pub cache: Option<CacheConfig>,
}

/// The shared response cache.
///
/// Configuring it does not cache anything — a route must set `cache: true`.
/// Caching is opt-in per route because the failure mode of caching the wrong
/// thing (one user's response served to another) is far worse than a cache
/// miss.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    /// Total bytes held. Bounds the cache by size rather than entry count,
    /// because ten 100 MB objects and ten thousand 10 KB ones are not the same
    /// cache.
    #[serde(default = "default_cache_size", deserialize_with = "de_byte_size")]
    pub max_size: u64,
    /// Largest single object stored. Enforced while the body streams in, so an
    /// oversized response is abandoned rather than buffered and then discarded.
    #[serde(default = "default_max_object", deserialize_with = "de_byte_size")]
    pub max_object_size: u64,
    /// Freshness for a response whose upstream said nothing about caching.
    #[serde(with = "humantime_serde", default = "d60")]
    pub default_ttl: Duration,
    /// How long a stale entry may still be served while it revalidates.
    #[serde(with = "humantime_serde", default = "d0")]
    pub stale_while_revalidate: Duration,
}

fn default_cache_size() -> u64 {
    256 * 1024 * 1024
}
fn default_max_object() -> u64 {
    8 * 1024 * 1024
}
fn d0() -> Duration {
    Duration::ZERO
}

/// What kind of failure may be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryOn {
    /// The connection was never established, so nothing was delivered.
    ConnectionFailure,
    /// The connection broke after it was established.
    TransportError,
}

impl<'de> Deserialize<'de> for RetryOn {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Accept a number so the common `on: [502, 503]` spelling gets a real
        // explanation rather than a type error.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Status(u16),
            Name(String),
        }

        match Raw::deserialize(d)? {
            Raw::Name(name) => match name.as_str() {
                "connection_failure" => Ok(Self::ConnectionFailure),
                "transport_error" => Ok(Self::TransportError),
                other => Err(serde::de::Error::custom(format!(
                    "`{other}` is not a retryable failure; expected `connection_failure` \
                     or `transport_error`"
                ))),
            },
            Raw::Status(code) => Err(serde::de::Error::custom(format!(
                "retrying on status {code} is not supported. Deciding after a status \
                 arrives means holding the whole response before sending any of it, \
                 which would break streaming and server-sent events. Retry on \
                 `connection_failure` and `transport_error`, and use upstream \
                 `health_check` to take a failing backend out of rotation."
            ))),
        }
    }
}

/// Retrying a failed upstream attempt.
///
/// See [`crate::retry`] — a connect failure is safe for any method because
/// nothing was delivered, while an error on an established connection is
/// retried only for idempotent methods.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryConfig {
    /// Retries *after* the first attempt, so `2` allows three deliveries.
    pub attempts: u32,
    #[serde(default = "default_retry_on")]
    pub on: Vec<RetryOn>,
    /// Retry POST and PATCH after an established connection fails.
    ///
    /// Off by default. Turning it on asserts the upstream tolerates receiving
    /// the same request twice — a claim about that service, not about the
    /// gateway.
    #[serde(default)]
    pub non_idempotent: bool,
}

fn default_retry_on() -> Vec<RetryOn> {
    vec![RetryOn::ConnectionFailure]
}

/// Cross-origin resource sharing.
///
/// See [`crate::cors`] — `credentials: true` alongside origin `*` is refused at
/// startup rather than honoured.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorsConfig {
    /// Exact origins (`https://app.example.com`), wildcard sub-domains
    /// (`https://*.preview.example.com`), or `*` for any.
    pub origins: Vec<String>,
    #[serde(default = "default_cors_methods")]
    pub methods: Vec<String>,
    /// Request headers a browser may send.
    #[serde(default = "default_cors_headers")]
    pub headers: Vec<String>,
    /// Response headers a browser may read.
    #[serde(default)]
    pub expose: Vec<String>,
    /// Allow cookies and `Authorization` on cross-origin requests.
    #[serde(default)]
    pub credentials: bool,
    /// How long a browser may cache the preflight.
    #[serde(with = "humantime_serde", default = "d600")]
    pub max_age: Duration,
}

fn default_cors_methods() -> Vec<String> {
    ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]
        .into_iter()
        .map(String::from)
        .collect()
}

fn default_cors_headers() -> Vec<String> {
    ["content-type", "authorization"]
        .into_iter()
        .map(String::from)
        .collect()
}

fn d600() -> Duration {
    Duration::from_secs(600)
}

/// What a rate limit counts, and against whom.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RateLimitKey {
    /// The client address. See `trusted_proxies` — this is the one that is a
    /// bypass if configured wrongly.
    #[default]
    Ip,
    /// The verified caller's subject. Requires a tier that reads a token.
    Identity,
    /// One bucket for the whole route, regardless of caller. Use to protect a
    /// fragile upstream rather than to be fair between clients.
    Route,
    /// An arbitrary request header, e.g. an API key.
    Header(String),
}

impl<'de> Deserialize<'de> for RateLimitKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        match raw.as_str() {
            "ip" => Ok(Self::Ip),
            "identity" => Ok(Self::Identity),
            "route" => Ok(Self::Route),
            other => match other.strip_prefix("header.") {
                Some(name) if !name.is_empty() => Ok(Self::Header(name.to_ascii_lowercase())),
                _ => Err(serde::de::Error::custom(format!(
                    "`{other}` is not a rate-limit key; expected `ip`, `identity`, `route`, \
                     or `header.<name>`"
                ))),
            },
        }
    }
}

/// A rate limit, applied per route.
///
/// ```yaml
/// rate_limit:
///   requests: 100
///   interval: 1m
///   key: ip
///   trusted_proxies: 1
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    pub requests: u64,
    #[serde(with = "humantime_serde", default = "d60")]
    pub interval: Duration,
    #[serde(default)]
    pub key: RateLimitKey,
    /// How many proxies sit in front of this gateway.
    ///
    /// `X-Forwarded-For` is appended to by each hop, so only the rightmost
    /// entries are trustworthy. **0 believes nothing in the header** and uses
    /// the socket peer — safe, but behind an ingress every client shares one
    /// bucket. Set it to the number of hops that actually front the gateway;
    /// setting it too high reads a client-supplied entry and hands out a fresh
    /// quota per forged address.
    #[serde(default)]
    pub trusted_proxies: usize,
    /// Ceiling on tracked keys. Keys come from requests, so this is what stops
    /// a flood of distinct callers growing the process without bound.
    ///
    /// Only meaningful for `counter: exact`; the sketch has fixed memory.
    #[serde(default = "default_max_keys")]
    pub max_keys: u64,
    #[serde(default)]
    pub counter: Counter,
}

/// How a rate limiter counts.
///
/// Both use the same sliding-window formula — the previous interval weighted by
/// how much of it is still in view — so a limit means the same thing either
/// way. They differ in what they trade for memory.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Counter {
    /// One counter per key, in a capacity-bounded cache.
    ///
    /// Exact: a caller is refused for its own traffic and nobody else's. The
    /// cost is an allocation per key and eviction under a key flood, which
    /// degrades limiting for the evicted keys.
    #[default]
    Exact,
    /// A shared count-min sketch (`pingora-limits`).
    ///
    /// Fixed memory and lock-free whatever the key cardinality — but
    /// **approximate, and it only ever over-counts**. Two keys can collide and
    /// one caller can be refused because of another's traffic. Worth it when
    /// the key space is huge and the limit is a blunt abuse control; wrong when
    /// the 429 is a promise to a specific customer.
    Sketch,
}

fn default_max_keys() -> u64 {
    100_000
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub tracing: Option<TracingConfig>,
}

/// Distributed tracing.
///
/// Enabling this makes the gateway a *participant* in a trace rather than a
/// relay: it continues an incoming `traceparent` and sends the upstream a new
/// one naming this hop, so the gateway's own latency stops being attributed to
/// the service behind it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TracingConfig {
    /// Where to send spans. Omit to propagate trace context without exporting
    /// anything — useful when the upstreams do their own collection.
    #[serde(default)]
    pub otlp: Option<OtlpConfig>,
    /// Fraction of *new* traces to sample, 0.0 to 1.0. A request that arrives
    /// with a sampling decision already made keeps it, whatever this says —
    /// re-deciding partway through produces a trace with holes in it.
    #[serde(default = "default_sample_ratio")]
    pub sample_ratio: f64,
}

fn default_sample_ratio() -> f64 {
    1.0
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OtlpConfig {
    /// OTLP/HTTP traces endpoint, e.g. `http://collector:4318/v1/traces`.
    pub endpoint: String,
}

/// Prometheus exposition.
///
/// On a listener of its own, never the traffic port: scrape endpoints are for
/// operators, and putting one on the public socket makes internal route names
/// and upstream health readable by anyone who can reach the gateway.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    pub listen: String,
    /// How often pool health is sampled into `gateway_pool_backends`.
    #[serde(with = "humantime_serde", default = "d10")]
    pub pool_sample_interval: Duration,
}

// ------------------------------------------------------------------- server

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Prefixes stripped from the request path before route matching. The
    /// remainder is the canonical sub-path.
    ///
    /// Several are allowed so one gateway can serve both a versioned mount
    /// (`/api/v1/users/...`) and the bare service paths (`/users/...`) that
    /// predate it, without clients having to move at the same time. `"/"`
    /// mounts at the root and therefore matches everything. Longest match wins
    /// regardless of order.
    #[serde(default = "default_mounts")]
    pub mounts: Vec<String>,
    /// Second listener serving only the `machine` tier.
    ///
    /// Machine routes are bound to their own socket rather than gated by a
    /// check on the shared one: an internal endpoint is then unreachable from
    /// the public listener as a matter of topology, not of correct code.
    #[serde(default)]
    pub internal_listen: Option<String>,
    /// Answered locally with `{"status":"ok"}`; never proxied.
    #[serde(default = "default_health_path")]
    pub health_path: String,
    #[serde(default = "default_service_name")]
    pub service_name: String,
    #[serde(default = "default_threads")]
    pub threads: usize,
    /// How long to drain in-flight requests on SIGTERM.
    ///
    /// Pingora's own default is 300s. Kubernetes SIGKILLs a pod at
    /// `terminationGracePeriodSeconds` (30s by default), so leaving it at 300
    /// means every rollout ends in a hard kill mid-drain. Keep this a little
    /// under whatever the pod spec allows.
    #[serde(with = "humantime_serde", default = "d25")]
    pub graceful_shutdown: Duration,
}

fn default_listen() -> String {
    "0.0.0.0:8080".into()
}
fn default_mounts() -> Vec<String> {
    vec!["/".into()]
}
fn default_health_path() -> String {
    "/health".into()
}
fn default_service_name() -> String {
    "lagos".into()
}
fn default_threads() -> usize {
    2
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            mounts: default_mounts(),
            internal_listen: None,
            health_path: default_health_path(),
            service_name: default_service_name(),
            threads: default_threads(),
            graceful_shutdown: d25(),
        }
    }
}

// ----------------------------------------------------------------- timeouts

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timeouts {
    #[serde(with = "humantime_serde", default = "d5")]
    pub connect: Duration,
    #[serde(with = "humantime_serde", default = "d30")]
    pub default: Duration,
    /// Applied to routes flagged `sse`, which must outlive the default budget.
    #[serde(with = "humantime_serde", default = "d120")]
    pub sse: Duration,
    /// Applied when the request carries a multipart/binary content type.
    #[serde(with = "humantime_serde", default = "d120")]
    pub upload: Duration,
    #[serde(with = "humantime_serde", default = "d60")]
    pub upstream_idle: Duration,

    // --- downstream (client-facing) budgets ------------------------------
    //
    // Pingora leaves most of these unset, which for an edge gateway means
    // unbounded: a client that opens a connection and then reads slowly, or
    // never, holds a worker task and an upstream connection for as long as it
    // likes. A few thousand such connections cost the attacker nothing and
    // take the gateway down. These are the knobs Pingora already exposes on
    // `ServerSession`; Lagos only gives them defaults and a name in the file.
    /// How long a single read from the client may stall — a request header
    /// arriving a byte at a time, or a body that stops mid-upload.
    ///
    /// Pingora's own default is 60s. 30s is plenty for a real client on a bad
    /// connection and halves what a slowloris costs to hold.
    #[serde(with = "humantime_serde", default = "d30")]
    pub downstream_read: Duration,
    /// How long a single write to the client may stall.
    ///
    /// Pingora leaves this unset, so a client that stops reading mid-response
    /// pins the exchange indefinitely. This is the slow-read half of
    /// slowloris, and it is the cheaper half to mount.
    #[serde(with = "humantime_serde", default = "d30")]
    pub downstream_write: Duration,
    /// How long to spend discarding a request body the gateway is not going to
    /// read — a rejected request that still has an upload behind it.
    ///
    /// Unset in Pingora. Without it, refusing a request with a large body can
    /// take longer than serving it would have.
    #[serde(with = "humantime_serde", default = "d5")]
    pub downstream_drain: Duration,
    /// How long an idle keepalive connection is held open for the next
    /// request.
    #[serde(with = "humantime_serde", default = "d60")]
    pub downstream_keepalive: Duration,
}

fn d5() -> Duration {
    Duration::from_secs(5)
}
fn d2() -> Duration {
    Duration::from_secs(2)
}
fn d10() -> Duration {
    Duration::from_secs(10)
}
fn d15() -> Duration {
    Duration::from_secs(15)
}
fn d25() -> Duration {
    Duration::from_secs(25)
}
fn d30() -> Duration {
    Duration::from_secs(30)
}
fn d60() -> Duration {
    Duration::from_secs(60)
}
fn d120() -> Duration {
    Duration::from_secs(120)
}
fn d300() -> Duration {
    Duration::from_secs(300)
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: d5(),
            default: d30(),
            sse: d120(),
            upload: d120(),
            upstream_idle: d60(),
            downstream_read: d30(),
            downstream_write: d30(),
            downstream_drain: d5(),
            downstream_keepalive: d60(),
        }
    }
}

// ------------------------------------------------------------------- limits

/// Caps that exist so a single request cannot hold a connection open forever
/// or stream an unbounded body. Timeouts cover the clock; this covers bytes.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Maximum request body, e.g. `50MiB`. Default 50 MiB.
    #[serde(default = "default_max_body", deserialize_with = "de_byte_size")]
    pub max_body: u64,
    /// Maximum bearer token accepted, in bytes. Default 8 KiB.
    ///
    /// A token is decoded and parsed as JSON to find its issuer, and then —
    /// if the issuer is one this gateway trusts — put through a signature
    /// check, all before any rate limit keyed on identity can apply. Capping
    /// the length first bounds what one unauthenticated request can cost.
    /// 8 KiB is far above any real access token, including Firebase's.
    #[serde(default = "default_max_token", deserialize_with = "de_byte_size")]
    pub max_token: u64,
    /// Requests one keepalive connection may serve before the gateway closes
    /// it. Default 1000; `0` means no limit.
    ///
    /// Pingora's default is no limit, which nginx's own documentation advises
    /// against: per-connection allocations are only reclaimed when the
    /// connection closes, so a long-lived connection is a slow leak and a
    /// held-open connection is a cheap way to keep one.
    #[serde(default = "default_keepalive_requests")]
    pub keepalive_requests: u32,
    /// Minimum rate, in bytes per second, at which a client must accept a
    /// response body. Off by default.
    ///
    /// Pingora turns this into a write timeout scaled by how much is being
    /// written, which `timeouts.downstream_write` alone cannot express: a
    /// large response legitimately takes longer than a small one. Leave it
    /// off for clients on genuinely poor links; turn it on where responses are
    /// big enough that a slow reader is worth the memory it holds.
    #[serde(default)]
    pub min_send_rate: Option<usize>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body: default_max_body(),
            max_token: default_max_token(),
            keepalive_requests: default_keepalive_requests(),
            min_send_rate: None,
        }
    }
}

fn default_max_token() -> u64 {
    8 * 1024
}

fn default_keepalive_requests() -> u32 {
    1000
}

fn default_max_body() -> u64 {
    50 * 1024 * 1024
}

fn de_byte_size<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        N(u64),
        S(String),
    }
    match Raw::deserialize(deserializer)? {
        Raw::N(n) => Ok(n),
        Raw::S(s) => parse_byte_size(&s).map_err(serde::de::Error::custom),
    }
}

fn parse_byte_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (n, unit) = s.split_at(split);
    if n.is_empty() {
        return Err(format!("not a size: {s}"));
    }
    let n: u64 = n.parse().map_err(|_| format!("not a size: {s}"))?;
    match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => Ok(n),
        "k" | "kb" | "kib" => Ok(n.saturating_mul(1024)),
        "m" | "mb" | "mib" => Ok(n.saturating_mul(1024 * 1024)),
        "g" | "gb" | "gib" => Ok(n.saturating_mul(1024 * 1024 * 1024)),
        other => Err(format!("unknown size unit {other}")),
    }
}

// ---------------------------------------------------------------- upstreams

/// A backend, or a pool of them.
///
/// The short form is a bare URL:
///
/// ```yaml
/// upstreams:
///   users: http://users:3000
/// ```
///
/// Several backends make it a pool, with optional weights, a balancing
/// algorithm and health checking:
///
/// ```yaml
/// upstreams:
///   users:
///     targets:
///       - http://users-1:3000
///       - url: http://users-2:3000
///         weight: 3
///     balance: round_robin
///     health_check:
///       path: /health
///       interval: 10s
/// ```
///
/// The two forms behave differently in one way worth knowing: a **single**
/// target keeps its hostname and is resolved per connection, so a DNS change
/// is picked up without a restart. A **pool** resolves its members at startup,
/// because the balancer works on addresses. In Kubernetes a Service name maps
/// to a stable ClusterIP, so this is usually invisible — but a pool pointed at
/// a headless service would pin the pods it saw at boot.
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// Always at least one after parsing.
    pub targets: Vec<UpstreamTargetConfig>,
    pub balance: Balance,
    /// What `balance: consistent` hashes on. Ignored by the other algorithms.
    pub hash_on: HashKey,
    pub health_check: Option<HealthCheckConfig>,
    pub circuit_breaker: Option<CircuitBreakerConfig>,
}

/// The request value a consistent hash is taken over.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum HashKey {
    /// The client address as seen on the socket. Sticky per caller — but
    /// behind an ingress every client shares the proxy's address, which makes
    /// this useless there. Prefer `identity` or a header in that case.
    Ip,
    /// The verified caller's subject. Sticky per user, across their devices
    /// and addresses.
    Identity,
    /// The request path. Sticky per resource, which is what an upstream cache
    /// wants, and the only key with no deployment caveat — so it is the default.
    #[default]
    Path,
    /// A request header, e.g. a tenant or session id.
    Header(String),
}

impl<'de> Deserialize<'de> for HashKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        match raw.as_str() {
            "ip" => Ok(Self::Ip),
            "identity" => Ok(Self::Identity),
            "path" => Ok(Self::Path),
            other => match other.strip_prefix("header.") {
                Some(name) if !name.is_empty() => Ok(Self::Header(name.to_ascii_lowercase())),
                _ => Err(serde::de::Error::custom(format!(
                    "`{other}` is not a hash key; expected `ip`, `identity`, `path`, \
                     or `header.<name>`"
                ))),
            },
        }
    }
}

/// Stop sending to an upstream that is failing.
///
/// Complements `health_check` rather than duplicating it: a health check asks
/// "is this backend up", a breaker asks "is this service working". An upstream
/// that accepts connections, passes its probe and then returns 500s or takes
/// 30 seconds to answer is invisible to the former.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakerConfig {
    /// Failures within `window` before the circuit opens.
    #[serde(default = "five")]
    pub failures: u32,
    #[serde(with = "humantime_serde", default = "d30")]
    pub window: Duration,
    /// How long to shed load before trying the upstream again.
    #[serde(with = "humantime_serde", default = "d10")]
    pub cooldown: Duration,
    /// Successful trials needed to close the circuit again.
    #[serde(default = "two_u32")]
    pub successes_to_close: u32,
    /// Trial requests allowed through at once while half-open. Kept small so a
    /// recovering upstream is not hit by the full load the moment the cooldown
    /// ends.
    #[serde(default = "one_u32")]
    pub max_trials: u32,
}

fn five() -> u32 {
    5
}
fn two_u32() -> u32 {
    2
}
fn one_u32() -> u32 {
    1
}

impl UpstreamConfig {
    /// A pool is anything the balancer has to choose between, or anything whose
    /// health is being tracked.
    pub fn is_pool(&self) -> bool {
        self.targets.len() > 1 || self.health_check.is_some()
    }
}

#[derive(Debug, Clone)]
pub struct UpstreamTargetConfig {
    pub url: String,
    /// Relative share of traffic. Equal weights by default.
    pub weight: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Balance {
    /// Weighted round robin. Predictable, and the right default: it needs no
    /// per-request state and spreads load evenly for uniform request costs.
    #[default]
    RoundRobin,
    /// Weighted random. Useful when many gateway instances would otherwise
    /// march in step through the same backend order.
    Random,
    /// Ketama consistent hashing on a key derived from the request.
    ///
    /// The same key lands on the same backend for as long as that backend is
    /// healthy, and adding or removing one moves only its share of keys rather
    /// than reshuffling everything. That is what makes an upstream's own cache
    /// worth having.
    ///
    /// Pair with `hash_on` to choose the key.
    Consistent,
}

/// Active health checking for a pool.
///
/// Without `path` this is a TCP connect check, which proves only that
/// something is listening. Naming a path makes it an HTTP check, which is what
/// actually tells you the service is able to serve.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(with = "humantime_serde", default = "d10")]
    pub interval: Duration,
    #[serde(with = "humantime_serde", default = "d2")]
    pub timeout: Duration,
    /// Consecutive successes before an unhealthy backend is used again.
    #[serde(default = "one")]
    pub healthy_after: usize,
    /// Consecutive failures before a backend is taken out of rotation.
    #[serde(default = "two")]
    pub unhealthy_after: usize,
}

fn one() -> usize {
    1
}
fn two() -> usize {
    2
}

impl<'de> Deserialize<'de> for UpstreamConfig {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Long {
            #[serde(default)]
            url: Option<String>,
            #[serde(default)]
            targets: Vec<UpstreamTargetConfig>,
            #[serde(default)]
            balance: Balance,
            #[serde(default)]
            hash_on: HashKey,
            #[serde(default)]
            health_check: Option<HealthCheckConfig>,
            #[serde(default)]
            circuit_breaker: Option<CircuitBreakerConfig>,
        }

        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = UpstreamConfig;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a URL string, or a mapping with `url` or `targets`")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UpstreamConfig {
                    targets: vec![UpstreamTargetConfig {
                        url: v.to_string(),
                        weight: 1,
                    }],
                    balance: Balance::default(),
                    hash_on: HashKey::default(),
                    health_check: None,
                    circuit_breaker: None,
                })
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                m: M,
            ) -> Result<Self::Value, M::Error> {
                let long = Long::deserialize(serde::de::value::MapAccessDeserializer::new(m))?;
                let targets = match (long.url, long.targets.is_empty()) {
                    (Some(_), false) => {
                        return Err(serde::de::Error::custom(
                            "an upstream sets both `url` and `targets`; use one or the other",
                        ));
                    }
                    (Some(url), true) => vec![UpstreamTargetConfig { url, weight: 1 }],
                    (None, false) => long.targets,
                    (None, true) => {
                        return Err(serde::de::Error::custom(
                            "an upstream needs a `url` or a non-empty `targets` list",
                        ));
                    }
                };
                Ok(UpstreamConfig {
                    targets,
                    balance: long.balance,
                    hash_on: long.hash_on,
                    health_check: long.health_check,
                    circuit_breaker: long.circuit_breaker,
                })
            }
        }

        d.deserialize_any(V)
    }
}

impl<'de> Deserialize<'de> for UpstreamTargetConfig {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Long {
            url: String,
            #[serde(default = "one")]
            weight: usize,
        }

        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = UpstreamTargetConfig;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a URL string, or a mapping with a `url` key")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UpstreamTargetConfig {
                    url: v.to_string(),
                    weight: 1,
                })
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                m: M,
            ) -> Result<Self::Value, M::Error> {
                let long = Long::deserialize(serde::de::value::MapAccessDeserializer::new(m))?;
                Ok(UpstreamTargetConfig {
                    url: long.url,
                    weight: long.weight,
                })
            }
        }

        d.deserialize_any(V)
    }
}

// --------------------------------------------------------------------- auth

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Trusted OIDC issuers. Any provider that signs JWTs and publishes a JWKS
    /// works — tokens are routed to one of these by their `iss` claim.
    #[serde(default)]
    pub jwt: Vec<JwtConfig>,
    #[serde(default)]
    pub firebase: Option<FirebaseConfig>,
    #[serde(default)]
    pub machine: Option<MachineConfig>,
}

/// Credential for service-to-service callers on the `machine` tier.
///
/// These callers are other systems, not people: there is no user token, only a
/// shared secret. Restricting *which* systems may reach the internal listener
/// is a network concern and belongs on that listener's ingress, not here.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineConfig {
    /// Header names to read the caller credential from, in order. Several are
    /// allowed because upstream guards accept more than one spelling.
    #[serde(default = "default_machine_headers")]
    pub headers: Vec<String>,
    pub secret: String,
}

/// Hand-written so the shared credential cannot reach a log line.
///
/// `ResolvedConfig` derives `Debug`, and one `tracing::debug!(?cfg)` or one
/// error that formats the configuration would otherwise print the secret that
/// every machine-tier caller authenticates with.
impl std::fmt::Debug for MachineConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MachineConfig")
            .field("headers", &self.headers)
            .field("secret", &Redacted(self.secret.len()))
            .finish()
    }
}

/// Stands in for a secret in `Debug` output, reporting only its length so a
/// "did the variable actually get set" question is still answerable.
pub(crate) struct Redacted(pub usize);

impl std::fmt::Debug for Redacted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted {} bytes>", self.0)
    }
}

fn default_machine_headers() -> Vec<String> {
    vec!["x-internal-api-key".into(), "x-api-key".into()]
}

/// One trusted OIDC issuer.
///
/// ```yaml
/// auth:
///   jwt:
///     - issuer: https://auth.example.com
///       audience: my-api
///       jwks_url: https://auth.example.com/.well-known/jwks.json
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtConfig {
    /// Must equal the token's `iss` exactly. Also how a token is routed when
    /// several issuers are configured.
    pub issuer: String,
    /// Accepted `aud` values. Required: without it, a token this issuer minted
    /// for a *different* service would be accepted here.
    pub audience: Vec<String>,
    /// Where the issuer publishes its signing keys. Defaults to the
    /// conventional `<issuer>/.well-known/jwks.json`.
    #[serde(default)]
    pub jwks_url: Option<String>,
    /// Signature algorithms to accept. The token's own `alg` header is checked
    /// against this list — it never selects its own verification.
    #[serde(default = "default_algorithms")]
    pub algorithms: Vec<String>,
    /// Claims that must be present beyond the standard set.
    #[serde(default)]
    pub required_claims: Vec<String>,
    #[serde(with = "humantime_serde", default = "d60")]
    pub clock_skew: Duration,
    /// Floor on how long fetched keys are cached, whatever the issuer's
    /// `Cache-Control` says.
    #[serde(with = "humantime_serde", default = "d300")]
    pub min_key_ttl: Duration,
}

fn default_algorithms() -> Vec<String> {
    vec!["RS256".into()]
}

impl JwtConfig {
    /// The keys endpoint, defaulted from the issuer when not given.
    pub fn resolved_jwks_url(&self) -> String {
        self.jwks_url.clone().unwrap_or_else(|| {
            format!(
                "{}/.well-known/jwks.json",
                self.issuer.trim_end_matches('/')
            )
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirebaseConfig {
    /// Firebase project IDs whose tokens are accepted. A token is routed to a
    /// project by its `iss` claim; unknown issuers are refused.
    ///
    /// Only project *IDs* are needed. Unlike the Firebase Admin SDK, verifying
    /// a token requires no service-account credentials, so this gateway holds
    /// no private keys.
    pub projects: Vec<String>,
    #[serde(default = "default_certs_url")]
    pub certs_url: String,
    #[serde(with = "humantime_serde", default = "d60")]
    pub clock_skew: Duration,
    /// Floor on how long fetched signing certificates are cached, regardless of
    /// the upstream `Cache-Control` header.
    #[serde(with = "humantime_serde", default = "d300")]
    pub min_cert_ttl: Duration,
}

fn default_certs_url() -> String {
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
        .to_string()
}

// ---------------------------------------------------------- header policies

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InjectConfig {
    /// Headers added to every upstream request. Any client-supplied copy is
    /// removed first, so these cannot be spoofed.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Used *instead of* `headers` on the internal listener.
    ///
    /// Machine-tier upstreams generally expect a different, higher-trust
    /// credential than public ones. Injecting the public credential there
    /// would merge two trust tiers that were deliberately separated.
    #[serde(default)]
    pub machine: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectConfig {
    /// Headers that cause an immediate 403 when a client sends them. Use for
    /// credentials and identity assertions the gateway produces itself.
    #[serde(default)]
    pub client_headers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardMode {
    /// Drop every client header except those listed. The safe default: a header
    /// an upstream trusts can never arrive just because a client sent it.
    Allowlist,
    /// Relay client headers untouched apart from explicit strips.
    Passthrough,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardConfig {
    #[serde(default = "default_forward_mode")]
    pub mode: ForwardMode,
    /// Client headers relayed upstream when present.
    #[serde(default = "default_forward_headers")]
    pub headers: Vec<String>,
    /// Relay the caller's `Authorization` header.
    ///
    /// Set to `false` once upstreams stop verifying tokens themselves and read
    /// identity from the injected headers instead — that is what stops a
    /// service from having to know anything about the identity provider.
    #[serde(default = "default_true")]
    pub authorization: bool,
    /// Send the client's `Host` upstream instead of the upstream's own
    /// authority. Off by default, matching what an HTTP client library does.
    #[serde(default)]
    pub preserve_host: bool,
    /// How many proxies in front of this gateway may be believed when they
    /// append to `X-Forwarded-For`.
    ///
    /// `0` — the default — means the gateway is the edge: the arriving chain
    /// was written by the caller, so it is discarded and `X-Forwarded-For` /
    /// `X-Real-IP` are rebuilt from the socket peer. Anything else would let a
    /// caller assert its own source address with one header, and every
    /// downstream control keyed on client IP — per-IP quotas, geo rules, fraud
    /// scoring, abuse blocklists, audit trails — would believe it.
    ///
    /// Set it to the number of hops that are genuinely yours: `1` behind a
    /// single cloud load balancer or ingress controller, `2` behind a CDN in
    /// front of that. Counting is from the right, so only addresses your own
    /// infrastructure appended are ever read.
    ///
    /// This is the same rule `rate_limit.trusted_proxies` uses, and the two
    /// should agree.
    #[serde(default)]
    pub trusted_proxies: usize,
}

fn default_forward_mode() -> ForwardMode {
    ForwardMode::Allowlist
}
fn default_true() -> bool {
    true
}

fn default_forward_headers() -> Vec<String> {
    [
        "user-agent",
        "x-forwarded-proto",
        "x-forwarded-host",
        "traceparent",
        "tracestate",
        "x-request-id",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

impl Default for ForwardConfig {
    fn default() -> Self {
        Self {
            mode: default_forward_mode(),
            headers: default_forward_headers(),
            authorization: true,
            preserve_host: false,
            trusted_proxies: 0,
        }
    }
}

// ----------------------------------------------------------------- identity

/// How the verified caller is described to upstreams.
///
/// This is the whole point of the gateway: a service that reads these headers
/// needs no identity-provider SDK and no token-verification code. Every one of
/// them is stripped from the client request before being set, so a caller can
/// never assert its own identity.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    #[serde(default = "default_subject_header")]
    pub subject_header: String,
    #[serde(default = "default_issuer_header")]
    pub issuer_header: String,
    /// Header carrying the full claim set as base64url-encoded JSON. Empty to omit.
    #[serde(default = "default_claims_header")]
    pub claims_header: String,
    /// Verified claims copied into upstream headers, as `header: claim`:
    ///
    /// ```yaml
    /// identity:
    ///   claims:
    ///     x-user-id:   sub
    ///     x-user-type: user_type
    /// ```
    ///
    /// Each header is stripped from the client request before being set, so a
    /// caller can never assert one itself. A claim that is **absent** leaves
    /// its header absent — it is not rendered as an empty value, because
    /// "unknown" and "empty" mean different things to an upstream that is
    /// making an authorization decision from them.
    #[serde(default)]
    pub claims: BTreeMap<String, ClaimMapping>,
    /// Mint a short-lived signed token alongside the plain headers.
    #[serde(default)]
    pub token: Option<IdentityTokenConfig>,
}

/// How one claim becomes one header.
///
/// The short form is the claim path. The long form exists for the case where
/// a JSON `null` is meaningful and distinct from the claim being absent:
///
/// ```yaml
/// x-employer-company-id:
///   claim: employerCompanyId
///   when_null: none          # explicitly "no employer", not "unknown"
/// ```
#[derive(Debug, Clone)]
pub struct ClaimMapping {
    /// Dotted claim path, e.g. `company.id`.
    pub claim: String,
    /// Emitted when the claim is present but JSON `null`. Without it, a null
    /// claim is treated like an absent one and no header is set.
    pub when_null: Option<String>,
}

impl<'de> Deserialize<'de> for ClaimMapping {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Long {
            claim: String,
            #[serde(default)]
            when_null: Option<String>,
        }

        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = ClaimMapping;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a claim name, or a mapping with a `claim` key")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(ClaimMapping {
                    claim: v.to_string(),
                    when_null: None,
                })
            }

            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                m: M,
            ) -> Result<Self::Value, M::Error> {
                let long = Long::deserialize(serde::de::value::MapAccessDeserializer::new(m))?;
                Ok(ClaimMapping {
                    claim: long.claim,
                    when_null: long.when_null,
                })
            }
        }

        d.deserialize_any(V)
    }
}

fn default_subject_header() -> String {
    "x-auth-subject".into()
}
fn default_issuer_header() -> String {
    "x-auth-issuer".into()
}
fn default_claims_header() -> String {
    "x-auth-claims".into()
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            subject_header: default_subject_header(),
            issuer_header: default_issuer_header(),
            claims_header: default_claims_header(),
            claims: BTreeMap::new(),
            token: None,
        }
    }
}

/// A per-request token proving the identity headers came from the gateway.
///
/// Without this, an upstream that trusts `x-auth-subject` is trusting the
/// network: anything that can reach the service can claim to be any user. With
/// it, the service verifies one short-lived signature using a single local key
/// — far cheaper than talking to the identity provider, and it does not fall
/// apart the moment a shared static credential leaks.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityTokenConfig {
    #[serde(default = "default_token_header")]
    pub header: String,
    /// HS256 signing secret. Keep it out of the file itself: `${SECRET}`.
    pub secret: String,
    #[serde(with = "humantime_serde", default = "d60")]
    pub ttl: Duration,
    /// `aud` claim, so a token minted for one service cannot be replayed at another.
    #[serde(default)]
    pub audience: Option<String>,
}

/// Hand-written for the same reason as [`MachineConfig`]: this secret signs
/// the identity tokens upstreams trust, so anyone who reads it out of a log can
/// mint any caller.
impl std::fmt::Debug for IdentityTokenConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityTokenConfig")
            .field("header", &self.header)
            .field("secret", &Redacted(self.secret.len()))
            .field("ttl", &self.ttl)
            .field("audience", &self.audience)
            .finish()
    }
}

fn default_token_header() -> String {
    "x-auth-token".into()
}

// ------------------------------------------------------------------- routes

/// The route table, either written inline or pointed at another file.
///
/// Inline is the common case and keeps the whole gateway in one document. A
/// separate file is worth it when routes change on a different schedule from
/// the rest of the configuration — a Kubernetes ConfigMap that operators edit
/// without touching listeners or credentials — because only that file is
/// re-read on the reload interval.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutesConfig {
    /// Load the groups below from this file instead of from this document.
    #[serde(default)]
    pub file: Option<String>,
    /// How often to re-read `file`. A ConfigMap update shows up as a changed
    /// mtime, so this is also how long a route change takes to land.
    #[serde(with = "humantime_serde", default = "d15")]
    pub reload: Duration,

    /// Path prefixes refused on the public listener outright. Anything here is
    /// unreachable from the internet even if some other group also matches it.
    #[serde(default)]
    pub internal: Vec<String>,
    /// Service-to-service endpoints, served only on the internal listener and
    /// only to a caller presenting the machine credential.
    #[serde(default)]
    pub machine: Vec<RouteConfig>,
    /// Proxied without a token. Injected credentials still apply.
    #[serde(default)]
    pub public: Vec<RouteConfig>,
    /// Usable signed-out, but personalised when a caller is signed in.
    #[serde(default)]
    pub optional: Vec<RouteConfig>,
    /// Require a verified bearer token.
    #[serde(default)]
    pub authenticated: Vec<RouteConfig>,
}

impl RoutesConfig {
    pub fn groups(&self) -> RouteGroups {
        RouteGroups {
            internal: self.internal.clone(),
            machine: self.machine.clone(),
            public: self.public.clone(),
            optional: self.optional.clone(),
            authenticated: self.authenticated.clone(),
        }
    }

    fn is_inline_empty(&self) -> bool {
        self.internal.is_empty()
            && self.machine.is_empty()
            && self.public.is_empty()
            && self.optional.is_empty()
            && self.authenticated.is_empty()
    }
}

// ----------------------------------------------------------------- resolved

/// Configuration with everything the request path needs precomputed. Built once
/// at startup so no request ever parses a URL or reads the environment.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub raw: GatewayConfig,
    pub upstreams: HashMap<String, UpstreamConfig>,
    pub injected_headers: Vec<(String, String)>,
    pub firebase_project_ids: Vec<String>,
    /// HS256 secret for identity-token minting.
    pub identity_secret: Option<Vec<u8>>,
    /// Caller credential for the machine tier.
    pub machine_secret: Option<String>,
    /// Injection set for the internal listener.
    pub machine_injected_headers: Vec<(String, String)>,
    /// `server.mounts`, normalized and sorted longest-first.
    pub base_paths: Vec<String>,
    /// Compiled cross-origin policy.
    pub cors: Option<crate::cors::Cors>,
    /// Environment variables the document referenced, for `validate` output.
    pub referenced_env: Vec<String>,
    /// Those that fell back to a default — the ones that differ between a
    /// laptop and a cluster.
    pub defaulted_env: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },

    // Not named `source`: the message already embeds it, and letting anyhow
    // walk it as a cause would print the same sentence twice.
    #[error("{path}: {error}")]
    Interpolate {
        path: String,
        error: InterpolateError,
    },

    #[error("{path}{location}: {message}")]
    Parse {
        path: String,
        location: String,
        message: String,
    },

    #[error("{0}")]
    Invalid(String),
}

impl ConfigError {
    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

/// Levenshtein distance, used only to suggest a near miss in an error message.
///
/// Bounded by a length guard so a pathological name cannot make validation
/// quadratic in the size of the file.
fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();

    for (i, ca) in a.chars().enumerate() {
        let mut cur: Vec<usize> = Vec::with_capacity(prev.len());
        cur.push(i.saturating_add(1));
        for (j, cb) in b.iter().enumerate() {
            let substitute = prev.get(j).copied().unwrap_or(usize::MAX);
            let delete = prev.get(j.saturating_add(1)).copied().unwrap_or(usize::MAX);
            let insert = cur.get(j).copied().unwrap_or(usize::MAX);
            let cost = usize::from(ca != *cb);
            cur.push(
                substitute
                    .saturating_add(cost)
                    .min(delete.saturating_add(1))
                    .min(insert.saturating_add(1)),
            );
        }
        prev = cur;
    }

    prev.last().copied().unwrap_or(0)
}

/// The closest known name to `name`, when one is close enough to be a typo.
pub fn did_you_mean<'a>(name: &str, known: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    if name.len() > 64 {
        return None;
    }
    known
        .into_iter()
        .filter(|k| k.len() <= 64)
        .map(|k| (edit_distance(name, k), k))
        // Two edits on a short name is already a stretch; beyond a third the
        // "did you mean" is noise rather than help.
        .filter(|(d, k)| *d <= 3.min(k.len().max(name.len()) / 2 + 1))
        .min_by_key(|(d, _)| *d)
        .map(|(_, k)| k)
}

/// Render a suggestion clause for an unknown name, e.g. `. Did you mean `users`?`
fn suggestion<'a>(name: &str, known: impl IntoIterator<Item = &'a str>) -> String {
    match did_you_mean(name, known) {
        Some(k) => format!(". Did you mean `{k}`?"),
        None => String::new(),
    }
}

impl GatewayConfig {
    /// Read, expand `${VAR}`, and parse a configuration file.
    pub fn load(path: &str) -> Result<(Self, Interpolated), ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_string(),
            source,
        })?;
        let (mut cfg, expanded) = Self::parse(path, &text)?;
        cfg.resolve_route_file_against(path);
        Ok((cfg, expanded))
    }

    /// Let `routes.file` be written relative to the document that names it.
    ///
    /// Tried as given first, so an absolute path or one relative to the working
    /// directory keeps working; only then relative to the config file. Without
    /// this, moving `gateway.yml` into a subdirectory silently breaks its route
    /// file, and the failure looks like a missing file rather than a wrong CWD.
    fn resolve_route_file_against(&mut self, config_path: &str) {
        let Some(file) = self.routes.file.as_ref() else {
            return;
        };
        if Path::new(file).exists() {
            return;
        }
        let Some(dir) = Path::new(config_path).parent() else {
            return;
        };
        let candidate = dir.join(file);
        if candidate.exists()
            && let Some(p) = candidate.to_str()
        {
            self.routes.file = Some(p.to_string());
        }
    }

    /// Expand and parse an in-memory document. Separate from [`Self::load`] so
    /// tests and `lagos validate` can work without touching the filesystem.
    pub fn parse(path: &str, text: &str) -> Result<(Self, Interpolated), ConfigError> {
        Self::parse_with(path, text, |name| std::env::var(name).ok())
    }

    /// As [`Self::parse`], but resolving `${VAR}` through `lookup` instead of
    /// the process environment.
    ///
    /// Tests use this rather than setting real environment variables: the
    /// environment is process-global, so a test that mutates it races every
    /// other test in the binary.
    pub fn parse_with<F>(
        path: &str,
        text: &str,
        lookup: F,
    ) -> Result<(Self, Interpolated), ConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let expanded =
            interpolate::interpolate(text, lookup).map_err(|error| ConfigError::Interpolate {
                path: path.to_string(),
                error,
            })?;

        let cfg: Self = serde_yaml_ng::from_str(&expanded.text).map_err(|e| {
            // serde_yaml reports a location against the *expanded* text. Line
            // numbers survive expansion because a substituted value may not
            // contain a newline; columns can shift, so only the line is shown.
            let location = e
                .location()
                .map(|l| format!(":{}:{}", l.line(), l.column()))
                .unwrap_or_default();
            ConfigError::Parse {
                path: path.to_string(),
                location,
                // serde_yaml repeats the position in the message; the prefix
                // already carries it along with the file name.
                message: strip_position(&e.to_string()),
            }
        })?;

        Ok((cfg, expanded))
    }

    /// Validate the document and precompute everything the request path needs.
    ///
    /// Every failure here is fatal at boot by design: a gateway that starts
    /// with an unresolvable upstream or a route pointing at nothing would serve
    /// a weaker policy than the one that was written down.
    pub fn resolve(self, expanded: &Interpolated) -> Result<ResolvedConfig, ConfigError> {
        let mut upstreams: HashMap<String, UpstreamConfig> = HashMap::new();
        for (name, up) in &self.upstreams {
            let mut normalized = up.clone();
            for target in &mut normalized.targets {
                let url = target.url.trim().trim_end_matches('/').to_string();
                if url.is_empty() {
                    return Err(ConfigError::invalid(format!(
                        "upstreams.{name}: a target URL is empty"
                    )));
                }
                // Parse now so a malformed URL is a startup error naming the
                // upstream, rather than a 502 on the first request to use it.
                crate::upstream::UpstreamTarget::parse(&url)
                    .map_err(|e| ConfigError::invalid(format!("upstreams.{name}: {e}")))?;
                if target.weight == 0 {
                    return Err(ConfigError::invalid(format!(
                        "upstreams.{name}: target `{url}` has weight 0. \
                         Remove it, or set `enabled: false` on the routes that use it — \
                         a zero weight would silently never be selected."
                    )));
                }
                target.url = url;
            }
            upstreams.insert(name.clone(), normalized);
        }

        let injected_headers = lower_pairs(&self.inject.headers);
        let machine_injected_headers = lower_pairs(&self.inject.machine);

        let firebase_project_ids = match &self.auth.firebase {
            Some(fb) => {
                let ids: Vec<String> = fb
                    .projects
                    .iter()
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty())
                    .collect();
                if ids.is_empty() {
                    return Err(ConfigError::invalid(
                        "auth.firebase.projects is empty; the gateway would reject every token",
                    ));
                }
                ids
            }
            None => Vec::new(),
        };

        let identity_secret = self
            .identity
            .token
            .as_ref()
            .map(|t| t.secret.clone().into_bytes());
        let machine_secret = self.auth.machine.as_ref().map(|m| m.secret.clone());

        let mut base_paths: Vec<String> = self
            .server
            .mounts
            .iter()
            .map(|p| crate::path::normalize_proxy_path(p).to_string())
            .collect();
        if base_paths.is_empty() {
            return Err(ConfigError::invalid(
                "server.mounts is empty; the gateway would match no request",
            ));
        }
        // Longest first so `/api/v1` wins over a root mount for the same request.
        base_paths.sort_by_key(|p| std::cmp::Reverse(p.len()));
        base_paths.dedup();

        if self.routes.file.is_some() && !self.routes.is_inline_empty() {
            return Err(ConfigError::invalid(
                "routes.file is set and routes are also written inline. \
                 Use one or the other, so there is a single place to read the route table.",
            ));
        }
        if self.routes.file.is_none() && self.routes.is_inline_empty() {
            return Err(ConfigError::invalid(
                "no routes are defined; the gateway would refuse every request. \
                 Add a `routes:` group, or point `routes.file` at a route file.",
            ));
        }

        for j in &self.auth.jwt {
            if j.issuer.trim().is_empty() {
                return Err(ConfigError::invalid("auth.jwt: `issuer` is empty"));
            }
            if j.audience.is_empty() {
                return Err(ConfigError::invalid(format!(
                    "auth.jwt `{}`: `audience` is required. Without it a token this issuer \
                     minted for another service would be accepted here.",
                    j.issuer
                )));
            }
            for alg in &j.algorithms {
                if parse_algorithm(alg).is_none() {
                    return Err(ConfigError::invalid(format!(
                        "auth.jwt `{}`: `{alg}` is not a supported algorithm. \
                         Use one of RS256, RS384, RS512, ES256, ES384, PS256, PS384, PS512, EdDSA.",
                        j.issuer
                    )));
                }
            }
        }

        for (name, up) in &self.upstreams {
            if let Some(cb) = &up.circuit_breaker {
                if cb.failures == 0 {
                    return Err(ConfigError::invalid(format!(
                        "upstreams.{name}.circuit_breaker.failures is 0, which would open the \
                         circuit before any request was made"
                    )));
                }
                if cb.successes_to_close == 0 || cb.max_trials == 0 {
                    return Err(ConfigError::invalid(format!(
                        "upstreams.{name}.circuit_breaker: `successes_to_close` and `max_trials` \
                         must be at least 1, or the circuit could never close again"
                    )));
                }
            }
        }

        if let Some(t) = &self.observability.tracing
            && !(0.0..=1.0).contains(&t.sample_ratio)
        {
            return Err(ConfigError::invalid(format!(
                "observability.tracing.sample_ratio is {}; it is a fraction between 0.0 and 1.0",
                t.sample_ratio
            )));
        }

        let cors = match &self.cors {
            Some(c) => Some(
                crate::cors::Cors::compile(c)
                    .map_err(|e| ConfigError::invalid(format!("cors: {e}")))?,
            ),
            None => None,
        };

        Ok(ResolvedConfig {
            cors,
            raw: self,
            upstreams,
            injected_headers,
            firebase_project_ids,
            identity_secret,
            machine_secret,
            machine_injected_headers,
            base_paths,
            referenced_env: expanded.referenced.clone(),
            defaulted_env: expanded.defaulted.clone(),
        })
    }
}

/// Drop serde_yaml's trailing ` at line N column M`, which duplicates the
/// location already shown next to the file name.
fn strip_position(message: &str) -> String {
    match message.rfind(" at line ") {
        Some(i) => message[..i].to_string(),
        None => message.to_string(),
    }
}

/// Map a configured algorithm name onto `jsonwebtoken`'s enum.
///
/// `none` and the HMAC family are deliberately absent: this path verifies with
/// a *public* key fetched from the issuer, and accepting an HMAC algorithm
/// there is the classic confusion attack, where the public key is replayed as
/// a shared secret.
pub fn parse_algorithm(name: &str) -> Option<jsonwebtoken::Algorithm> {
    use jsonwebtoken::Algorithm::*;
    match name.to_ascii_uppercase().as_str() {
        "RS256" => Some(RS256),
        "RS384" => Some(RS384),
        "RS512" => Some(RS512),
        "ES256" => Some(ES256),
        "ES384" => Some(ES384),
        "PS256" => Some(PS256),
        "PS384" => Some(PS384),
        "PS512" => Some(PS512),
        "EDDSA" => Some(EdDSA),
        _ => None,
    }
}

fn lower_pairs(map: &BTreeMap<String, String>) -> Vec<(String, String)> {
    map.iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect()
}

impl ResolvedConfig {
    /// Semantic checks that need the route table, which may be loaded from a
    /// separate file after the document itself is parsed.
    ///
    /// Run at boot *and* on every reload, so a route file that points at a
    /// missing upstream is rejected and the previous table keeps serving.
    /// Validate a built table, including specs that failed to parse.
    ///
    /// Prefer this over [`Self::validate_routes`]: a `bind:` that did not parse
    /// is recorded on the table rather than dropped, and skipping this check
    /// would run a route whose ownership rule silently does nothing.
    pub fn validate_table(&self, table: &crate::routes::RouteTable) -> Result<(), ConfigError> {
        if let Some(first) = table.errors().first() {
            return Err(ConfigError::invalid(first.clone()));
        }
        self.validate_routes(table.routes())
    }

    pub fn validate_routes(&self, routes: &[RouteConfig]) -> Result<(), ConfigError> {
        let known: Vec<&str> = self.upstreams.keys().map(String::as_str).collect();
        let mut seen: BTreeMap<&str, &str> = BTreeMap::new();

        for r in routes {
            if r.prefix.is_empty() {
                return Err(ConfigError::invalid(format!(
                    "route `{}`: prefix is empty; it would match every request",
                    r.id
                )));
            }
            if !self.upstreams.contains_key(&r.upstream) {
                return Err(ConfigError::invalid(format!(
                    "route `{}` names upstream `{}`, which is not defined{}",
                    r.id,
                    r.upstream,
                    suggestion(&r.upstream, known.iter().copied()),
                )));
            }
            if let Some(prev) = seen.insert(r.id.as_str(), r.prefix.as_str()) {
                return Err(ConfigError::invalid(format!(
                    "two routes share the id `{}` (`{}` and `{}`). \
                     Ids name the route in logs and metrics, so they must be unique.",
                    r.id, prev, r.prefix,
                )));
            }
        }

        // A binding that names an identity claim on a tier that never reads a
        // token would be a check that can only ever refuse. Catch it here
        // rather than letting every request to that route 403 in production.
        for r in routes {
            if !r.bindings.is_empty() && !r.auth.verifies() {
                return Err(ConfigError::invalid(format!(
                    "route `{}` is in the `{}` group but declares `bind`. \
                     A binding compares against the caller's identity, which is \
                     never read on that tier, so every request would be refused.",
                    r.id,
                    r.auth.group(),
                )));
            }
        }

        for r in routes {
            if r.cache && self.raw.cache.is_none() {
                return Err(ConfigError::invalid(format!(
                    "route `{}` sets `cache: true` but no `cache:` block is configured",
                    r.id
                )));
            }
            if r.cache && r.auth.verifies() && !r.cache_authenticated {
                return Err(ConfigError::invalid(format!(
                    "route `{}` is in the `{}` group and sets `cache: true`. Responses there are \
                     usually personalised, and sharing one between callers is a data leak rather \
                     than a slow page. If the upstream sends correct `Cache-Control` and you mean \
                     it, add `cache_authenticated: true`.",
                    r.id,
                    r.auth.group(),
                )));
            }
        }

        let machine_routes = routes.iter().filter(|r| r.auth.is_machine()).count();
        if machine_routes > 0 {
            if self.raw.auth.machine.is_none() {
                return Err(ConfigError::invalid(format!(
                    "{machine_routes} machine-tier route(s) are defined but `auth.machine` is not \
                     configured; there would be no credential to check them against"
                )));
            }
            if self.raw.server.internal_listen.is_none() {
                return Err(ConfigError::invalid(format!(
                    "{machine_routes} machine-tier route(s) are defined but \
                     `server.internal_listen` is unset; they would be unreachable"
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
upstreams:
  users: http://users:3000
routes:
  public:
    - prefix: /users
      upstream: users
"#;

    /// The single URL of a one-target upstream, for assertions.
    fn url_of(r: &ResolvedConfig, name: &str) -> String {
        r.upstreams[name]
            .targets
            .first()
            .expect("at least one target")
            .url
            .clone()
    }

    fn parse(text: &str) -> Result<ResolvedConfig, ConfigError> {
        let (cfg, expanded) = GatewayConfig::parse("test.yml", text)?;
        cfg.resolve(&expanded)
    }

    #[test]
    fn the_minimal_document_needs_no_environment() {
        let r = parse(MINIMAL).expect("a two-key document should be a valid gateway");
        assert_eq!(r.raw.server.listen, "0.0.0.0:8080");
        assert_eq!(r.base_paths, vec![""], "the default mount is the root");
        assert_eq!(r.raw.server.health_path, "/health");
        assert_eq!(url_of(&r, "users"), "http://users:3000");
        assert!(r.referenced_env.is_empty());
    }

    #[test]
    fn a_trailing_slash_on_an_upstream_is_trimmed() {
        let r = parse(
            r#"
upstreams:
  users: http://users:3000/
routes:
  public: [{ prefix: /users, upstream: users }]
"#,
        )
        .expect("valid");
        assert_eq!(url_of(&r, "users"), "http://users:3000");
    }

    #[test]
    fn the_long_upstream_form_is_accepted() {
        let r = parse(
            r#"
upstreams:
  users:
    url: http://users:3000
routes:
  public: [{ prefix: /users, upstream: users }]
"#,
        )
        .expect("valid");
        assert_eq!(url_of(&r, "users"), "http://users:3000");
    }

    #[test]
    fn a_malformed_upstream_url_fails_at_startup() {
        let e = parse(
            r#"
upstreams:
  users: ftp://users:3000
routes:
  public: [{ prefix: /users, upstream: users }]
"#,
        )
        .expect_err("an unsupported scheme must not reach the request path");
        assert!(e.to_string().contains("upstreams.users"), "{e}");
    }

    #[test]
    fn an_unknown_key_is_rejected_rather_than_ignored() {
        let e = parse(
            r#"
servr:
  listen: 0.0.0.0:1
upstreams:
  users: http://users:3000
routes:
  public: [{ prefix: /users, upstream: users }]
"#,
        )
        .expect_err("a misspelled top-level key must not be silently ignored");
        assert!(matches!(e, ConfigError::Parse { .. }), "{e:?}");
    }

    #[test]
    fn a_parse_error_reports_a_line() {
        let e = parse("upstreams:\n  users: http://u:1\nroutes:\n  public: [oops\n")
            .expect_err("malformed YAML");
        match e {
            ConfigError::Parse { location, .. } => {
                assert!(!location.is_empty(), "the error should carry a line number")
            }
            other => panic!("expected a parse error, got {other:?}"),
        }
    }

    /// Parse with a fixed set of variables, never the process environment.
    fn parse_env(text: &str, vars: &[(&str, &str)]) -> Result<ResolvedConfig, ConfigError> {
        let map: std::collections::HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        let (cfg, expanded) = GatewayConfig::parse_with("test.yml", text, |n| map.get(n).cloned())?;
        cfg.resolve(&expanded)
    }

    #[test]
    fn env_indirection_works_without_a_dedicated_field() {
        let r = parse_env(
            r#"
upstreams:
  users: ${C1_URL}
  carts: ${C1_MISSING:-http://localhost:3001}
routes:
  public: [{ prefix: /users, upstream: users }]
"#,
            &[("C1_URL", "http://real:9000")],
        )
        .expect("valid");
        assert_eq!(url_of(&r, "users"), "http://real:9000");
        assert_eq!(url_of(&r, "carts"), "http://localhost:3001");
        assert_eq!(r.referenced_env, vec!["C1_URL", "C1_MISSING"]);
        assert_eq!(r.defaulted_env, vec!["C1_MISSING"]);
    }

    #[test]
    fn a_required_variable_that_is_unset_is_still_fatal() {
        let e = parse(
            r#"
inject:
  headers:
    x-api-key: ${C2_DEFINITELY_UNSET}
upstreams:
  users: http://users:3000
routes:
  public: [{ prefix: /users, upstream: users }]
"#,
        )
        .expect_err("an unset credential must not start the gateway");
        assert!(matches!(e, ConfigError::Interpolate { .. }), "{e:?}");
    }

    #[test]
    fn injected_header_names_are_lowercased() {
        let r = parse_env(
            r#"
inject:
  headers:
    X-API-Key: ${C3_KEY}
upstreams:
  users: http://users:3000
routes:
  public: [{ prefix: /users, upstream: users }]
"#,
            &[("C3_KEY", "secret")],
        )
        .expect("valid");
        assert_eq!(
            r.injected_headers,
            vec![("x-api-key".to_string(), "secret".to_string())]
        );
    }

    #[test]
    fn routes_may_not_be_both_inline_and_in_a_file() {
        let e = parse(
            r#"
upstreams:
  users: http://users:3000
routes:
  file: routes.yml
  public: [{ prefix: /users, upstream: users }]
"#,
        )
        .expect_err("two sources for one table is ambiguous");
        assert!(e.to_string().contains("one or the other"), "{e}");
    }

    #[test]
    fn a_document_with_no_routes_at_all_is_refused() {
        let e = parse("upstreams:\n  users: http://users:3000\n")
            .expect_err("a gateway with no routes refuses everything");
        assert!(e.to_string().contains("no routes are defined"), "{e}");
    }

    #[test]
    fn parses_human_body_sizes() {
        assert_eq!(parse_byte_size("1024").unwrap(), 1024);
        assert_eq!(parse_byte_size("1KiB").unwrap(), 1024);
        assert_eq!(parse_byte_size("50MiB").unwrap(), 50 * 1024 * 1024);
        assert_eq!(parse_byte_size("50MB").unwrap(), 50 * 1024 * 1024);
    }

    #[test]
    fn omitted_limits_default_to_fifty_mib() {
        let r = parse(MINIMAL).expect("valid");
        assert_eq!(r.raw.limits.max_body, 50 * 1024 * 1024);
    }

    #[test]
    fn durations_are_written_the_human_way() {
        let r = parse(
            r#"
timeouts:
  connect: 2s
  default: 1m
upstreams:
  users: http://users:3000
routes:
  public: [{ prefix: /users, upstream: users }]
"#,
        )
        .expect("valid");
        assert_eq!(r.raw.timeouts.connect, Duration::from_secs(2));
        assert_eq!(r.raw.timeouts.default, Duration::from_secs(60));
    }

    fn table(yaml: &str) -> Result<crate::routes::RouteTable, ConfigError> {
        let (cfg, expanded) = GatewayConfig::parse("test.yml", yaml)?;
        let resolved = cfg.resolve(&expanded)?;
        let table = crate::routes::RouteTable::build(resolved.raw.routes.groups());
        resolved.validate_table(&table)?;
        Ok(table)
    }

    #[test]
    fn a_binding_is_parsed_from_the_route() {
        let t = table(
            r#"
upstreams: { realtime: http://r:1 }
routes:
  authenticated:
    - prefix: /events
      upstream: realtime
      bind:
        query.merchantId: identity.company_id
"#,
        )
        .expect("valid");
        let r = t.match_route("events", "GET").expect("route");
        assert_eq!(r.bindings.len(), 1);
        assert_eq!(
            r.bindings[0].describe(),
            "query.merchantId == identity.company_id"
        );
    }

    #[test]
    fn a_malformed_binding_fails_at_startup() {
        let e = table(
            r#"
upstreams: { realtime: http://r:1 }
routes:
  authenticated:
    - prefix: /events
      upstream: realtime
      bind:
        body.merchantId: identity.company_id
"#,
        )
        .expect_err("an unparseable binding must not start the gateway");
        assert!(e.to_string().contains("not a bindable source"), "{e}");
    }

    #[test]
    fn a_binding_on_a_tokenless_tier_is_refused() {
        // On `public` no token is read, so the comparison could only ever fail
        // — a rule that refuses everything is a configuration mistake.
        let e = table(
            r#"
upstreams: { realtime: http://r:1 }
routes:
  public:
    - prefix: /events
      upstream: realtime
      bind:
        query.merchantId: identity.company_id
"#,
        )
        .expect_err("a binding needs a tier that reads a token");
        assert!(
            e.to_string().contains("every request would be refused"),
            "{e}"
        );
    }

    #[test]
    fn claim_mappings_accept_both_forms() {
        let (cfg, expanded) = GatewayConfig::parse(
            "test.yml",
            r#"
identity:
  claims:
    x-user-id: sub
    x-employer-company-id:
      claim: employerCompanyId
      when_null: none
upstreams: { u: http://u:1 }
routes:
  public: [{ prefix: /a, upstream: u }]
"#,
        )
        .expect("parses");
        let r = cfg.resolve(&expanded).expect("resolves");
        let claims = &r.raw.identity.claims;
        assert_eq!(claims["x-user-id"].claim, "sub");
        assert_eq!(claims["x-user-id"].when_null, None);
        assert_eq!(claims["x-employer-company-id"].claim, "employerCompanyId");
        assert_eq!(
            claims["x-employer-company-id"].when_null.as_deref(),
            Some("none")
        );
    }

    #[test]
    fn suggests_a_near_miss_for_an_unknown_name() {
        assert_eq!(
            did_you_mean("users-v3", ["users-v2", "orders"]),
            Some("users-v2")
        );
        assert_eq!(
            did_you_mean("loylaty", ["loyalty", "orders"]),
            Some("loyalty")
        );
        assert_eq!(did_you_mean("completely-different", ["users"]), None);
    }
}
