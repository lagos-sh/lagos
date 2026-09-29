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
pub mod schema;

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::time::Duration;

use schemars::JsonSchema;
use serde::Deserialize;

pub use interpolate::{InterpolateError, Interpolated, interpolate};

use crate::routes::{RouteConfig, RouteGroups};

// ---------------------------------------------------------------- top level

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// Inherited route policies; route values replace each whole field.
    #[serde(default)]
    pub defaults: RouteDefaults,
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
    /// How upstream names are resolved.
    #[serde(default)]
    pub dns: DnsConfig,
    /// Cross-origin policy, applied to every route.
    #[serde(default)]
    pub cors: Option<CorsConfig>,
    /// Response cache. Configures the store; routes opt in individually.
    #[serde(default)]
    pub cache: Option<CacheConfig>,
}

/// Global policies for routes that omit the corresponding field.
/// Auth, cache and listener selection are deliberately excluded.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouteDefaults {
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    #[serde(default)]
    pub retry: Option<RetryConfig>,
    /// Omit to allow any method; an explicit empty list also allows any.
    #[serde(default, deserialize_with = "crate::routes::present_methods")]
    #[schemars(with = "Vec<String>")]
    #[schemars(transform = schema::inherited_policy)]
    pub methods: Option<Vec<String>>,
}

/// The shared response cache.
///
/// Configuring it does not cache anything — a route must set `cache: true`.
/// Caching is opt-in per route because the failure mode of caching the wrong
/// thing (one user's response served to another) is far worse than a cache
/// miss.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    /// Total bytes held. Bounds the cache by size rather than entry count,
    /// because ten 100 MB objects and ten thousand 10 KB ones are not the same
    /// cache.
    #[serde(default = "default_cache_size", deserialize_with = "de_byte_size")]
    #[schemars(schema_with = "schema::byte_size")]
    pub max_size: u64,
    /// Largest single object stored. Enforced while the body streams in, so an
    /// oversized response is abandoned rather than buffered and then discarded.
    #[serde(default = "default_max_object", deserialize_with = "de_byte_size")]
    #[schemars(schema_with = "schema::byte_size")]
    pub max_object_size: u64,
    /// Freshness for a response whose upstream said nothing about caching.
    #[serde(with = "humantime_serde", default = "d60")]
    #[schemars(with = "String")]
    pub default_ttl: Duration,
    /// How long a stale entry may still be served while it revalidates.
    #[serde(with = "humantime_serde", default = "d0")]
    #[schemars(with = "String")]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, JsonSchema)]
#[schemars(with = "schema::RetryFailure")]
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
#[derive(Debug, Clone, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Deserialize, JsonSchema)]
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
    #[schemars(with = "String")]
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
#[derive(Debug, Clone, Default, PartialEq, Eq, JsonSchema)]
#[schemars(with = "schema::RateSelector")]
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
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    pub requests: u64,
    #[serde(with = "humantime_serde", default = "d60")]
    #[schemars(with = "String")]
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
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

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Deserialize, JsonSchema)]
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

#[derive(Debug, Clone, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    pub listen: String,
    /// How often pool health is sampled into `gateway_pool_backends`.
    #[serde(with = "humantime_serde", default = "d10")]
    #[schemars(with = "String")]
    pub pool_sample_interval: Duration,
}

// ------------------------------------------------------------------- server

#[derive(Debug, Clone, Deserialize, JsonSchema)]
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
    /// Kernel-level keepalive on accepted connections, so a peer that vanished
    /// without closing — a yanked cable, a NAT table entry that expired — is
    /// detected and its socket released instead of being held until an
    /// application timeout notices. It cannot close a connection whose peer is
    /// still answering.
    #[serde(default)]
    pub tcp_keepalive: Option<TcpKeepaliveConfig>,
    /// How long to wait after SIGTERM before starting to drain.
    ///
    /// Unset by default. The window exists so a load balancer notices this
    /// instance going away and stops sending it new connections *before* the
    /// ones in flight are cut. Whatever is set here is spent before
    /// `graceful_shutdown` begins, so the two together must still fit inside
    /// the process manager's own kill deadline.
    #[serde(default, with = "humantime_serde::option")]
    #[schemars(with = "Option<String>")]
    pub shutdown_grace: Option<Duration>,
    /// How long to drain in-flight requests on SIGTERM.
    ///
    /// Pingora's own default is 300s. Kubernetes SIGKILLs a pod at
    /// `terminationGracePeriodSeconds` (30s by default), so leaving it at 300
    /// means every rollout ends in a hard kill mid-drain. Keep this a little
    /// under whatever the pod spec allows.
    #[serde(with = "humantime_serde", default = "d25")]
    #[schemars(with = "String")]
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

/// TCP keepalive probing on accepted connections.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TcpKeepaliveConfig {
    /// Idle time before the first probe.
    #[serde(with = "humantime_serde", default = "d60")]
    #[schemars(with = "String")]
    pub idle: Duration,
    /// Gap between probes.
    #[serde(with = "humantime_serde", default = "d10")]
    #[schemars(with = "String")]
    pub interval: Duration,
    /// Unanswered probes before the connection is dropped.
    #[serde(default = "default_keepalive_count")]
    pub count: usize,
}

fn default_keepalive_count() -> usize {
    6
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
            tcp_keepalive: None,
            shutdown_grace: None,
            graceful_shutdown: d25(),
        }
    }
}

// ----------------------------------------------------------------- timeouts

#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Timeouts {
    #[serde(with = "humantime_serde", default = "d5")]
    #[schemars(with = "String")]
    pub connect: Duration,
    #[serde(with = "humantime_serde", default = "d30")]
    #[schemars(with = "String")]
    pub default: Duration,
    /// Applied to routes flagged `sse`, which must outlive the default budget.
    #[serde(with = "humantime_serde", default = "d120")]
    #[schemars(with = "String")]
    pub sse: Duration,
    /// Applied when the request carries a multipart/binary content type.
    #[serde(with = "humantime_serde", default = "d120")]
    #[schemars(with = "String")]
    pub upload: Duration,
    #[serde(with = "humantime_serde", default = "d60")]
    #[schemars(with = "String")]
    pub upstream_idle: Duration,

    // --- downstream (client-facing) budgets ------------------------------
    //
    // Pingora leaves most of these unset, which for an edge gateway means
    // unbounded: a client that opens a connection and then reads slowly, or
    // never, holds a worker task and an upstream connection for as long as it
    // likes. A few thousand such connections cost the attacker nothing and
    // take the gateway down. These are the knobs Pingora already exposes on
    // `ServerSession`; Lagos only gives them defaults and a name in the file.
    /// Absolute deadline for receiving a complete request header, and the
    /// maximum gap between reads while receiving the body.
    ///
    /// Pingora's own default is 60s. 30s is plenty for a real client on a bad
    /// connection and halves what a slowloris costs to hold.
    #[serde(with = "humantime_serde", default = "d30")]
    #[schemars(with = "String")]
    pub downstream_read: Duration,
    /// How long a single write to the client may stall.
    ///
    /// Pingora leaves this unset, so a client that stops reading mid-response
    /// pins the exchange indefinitely. This is the slow-read half of
    /// slowloris, and it is the cheaper half to mount.
    #[serde(with = "humantime_serde", default = "d30")]
    #[schemars(with = "String")]
    pub downstream_write: Duration,
    /// How long to spend discarding a request body the gateway is not going to
    /// read — a rejected request that still has an upload behind it.
    ///
    /// Unset in Pingora. Without it, refusing a request with a large body can
    /// take longer than serving it would have.
    #[serde(with = "humantime_serde", default = "d5")]
    #[schemars(with = "String")]
    pub downstream_drain: Duration,
    /// How long an idle keepalive connection is held open for the next
    /// request.
    #[serde(with = "humantime_serde", default = "d60")]
    #[schemars(with = "String")]
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
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Maximum request body, e.g. `50MiB`. Default 50 MiB.
    #[serde(default = "default_max_body", deserialize_with = "de_byte_size")]
    #[schemars(schema_with = "schema::byte_size")]
    pub max_body: u64,
    /// Maximum bearer token accepted, in bytes. Default 8 KiB.
    ///
    /// A token is decoded and parsed as JSON to find its issuer, and then —
    /// if the issuer is one this gateway trusts — put through a signature
    /// check, all before any rate limit keyed on identity can apply. Capping
    /// the length first bounds what one unauthenticated request can cost.
    /// 8 KiB is far above any real access token, including Firebase's.
    #[serde(default = "default_max_token", deserialize_with = "de_byte_size")]
    #[schemars(schema_with = "schema::byte_size")]
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
    /// Refuse connections from an address that opens them too quickly.
    ///
    /// Off by default, and deliberately so: an address is not a caller. Behind
    /// an ingress controller *every* connection arrives from one address, and
    /// turning this on there would throttle the whole gateway. It is the right
    /// control only where Lagos is genuinely the edge.
    #[serde(default)]
    pub connections_per_ip: Option<ConnectionLimitConfig>,
    /// Idle upstream connections kept for reuse, per upstream. Pingora's own
    /// default is 128; it is exposed here because it is the main thing
    /// determining the gateway's steady-state memory once it is busy.
    #[serde(default = "default_upstream_pool")]
    pub upstream_pool: usize,
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
            connections_per_ip: None,
            upstream_pool: default_upstream_pool(),
        }
    }
}

fn default_max_token() -> u64 {
    8 * 1024
}

// ---------------------------------------------------------------------- dns

/// Upstream name resolution.
///
/// A single-target upstream keeps its hostname so that a record change is
/// picked up without a restart. That means a name is resolved on the way to
/// choosing a peer, and the only question is how often and on which thread.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    /// How long a resolved name is reused. `0s` resolves on every request.
    ///
    /// This is the delay before a record change is noticed, traded against a
    /// resolver round trip per request. 30s is what a proxy usually settles on
    /// and is far shorter than the time a rolling deployment takes anyway.
    ///
    /// Failures are never cached: one bad lookup must not become a TTL-long
    /// outage for that upstream after the resolver has recovered.
    #[serde(with = "humantime_serde", default = "d30")]
    #[schemars(with = "String")]
    pub cache_ttl: Duration,
    /// Maximum names held. Upstream names come from configuration rather than
    /// from requests, so this cannot be flooded by a caller; it is here because
    /// an unbounded map in a long-lived process is worth avoiding regardless.
    #[serde(default = "default_dns_max_entries")]
    pub max_entries: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            cache_ttl: d30(),
            max_entries: default_dns_max_entries(),
        }
    }
}

fn default_dns_max_entries() -> u64 {
    1024
}

fn default_keepalive_requests() -> u32 {
    1000
}

fn default_upstream_pool() -> usize {
    128
}

/// How fast one address may open new connections.
///
/// This counts *accepts*, not live connections: the accept hook is never told
/// about a close, so a population count kept from there would drift upward
/// until it refused everyone. The absolute request-header deadline closes
/// sockets that never finish a header, but long-lived responses can still
/// accumulate; this is not a concurrent-connection ceiling.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectionLimitConfig {
    /// New connections allowed per `interval` from one address.
    pub connections: u64,
    #[serde(with = "humantime_serde", default = "d1")]
    #[schemars(with = "String")]
    pub interval: Duration,
    /// Addresses tracked at once. The store is bounded because its keys come
    /// from the network: without a cap, the memory-exhaustion bug this setting
    /// exists to prevent would simply move into the limiter.
    #[serde(default = "default_max_tracked")]
    pub max_tracked: u64,
}

impl ConnectionLimitConfig {
    /// Reuse the request limiter rather than growing a second counter with its
    /// own sliding-window bugs. The key is always the socket peer — at accept
    /// time nothing has been parsed, so there is no header to trust and no
    /// forwarded chain to count back through.
    pub fn as_rate_limit(&self) -> RateLimitConfig {
        RateLimitConfig {
            requests: self.connections,
            interval: self.interval,
            key: RateLimitKey::Ip,
            trusted_proxies: 0,
            max_keys: self.max_tracked,
            counter: Counter::Exact,
        }
    }
}

fn default_max_tracked() -> u64 {
    100_000
}

fn d1() -> Duration {
    Duration::from_secs(1)
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
#[derive(Debug, Clone, JsonSchema)]
#[schemars(with = "schema::Upstream")]
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
#[derive(Debug, Clone, Default, PartialEq, Eq, JsonSchema)]
#[schemars(with = "schema::HashSelector")]
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
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreakerConfig {
    /// Failures within `window` before the circuit opens.
    #[serde(default = "five")]
    pub failures: u32,
    #[serde(with = "humantime_serde", default = "d30")]
    #[schemars(with = "String")]
    pub window: Duration,
    /// How long to shed load before trying the upstream again.
    #[serde(with = "humantime_serde", default = "d10")]
    #[schemars(with = "String")]
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

#[derive(Debug, Clone, JsonSchema)]
#[schemars(with = "schema::Target")]
pub struct UpstreamTargetConfig {
    pub url: String,
    /// Relative share of traffic. Equal weights by default.
    pub weight: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(with = "humantime_serde", default = "d10")]
    #[schemars(with = "String")]
    pub interval: Duration,
    #[serde(with = "humantime_serde", default = "d2")]
    #[schemars(with = "String")]
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

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(transform = schema::upstream_source)]
struct UpstreamDetails {
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

impl<'de> Deserialize<'de> for UpstreamConfig {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
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
                let long =
                    UpstreamDetails::deserialize(serde::de::value::MapAccessDeserializer::new(m))?;
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

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct UpstreamTargetDetails {
    url: String,
    #[serde(default = "one")]
    weight: usize,
}

impl<'de> Deserialize<'de> for UpstreamTargetConfig {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
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
                let long = UpstreamTargetDetails::deserialize(
                    serde::de::value::MapAccessDeserializer::new(m),
                )?;
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

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
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
    #[serde(default)]
    pub client_keys: Option<ClientKeysConfig>,
    /// Cookies a token may also be read from, in order, when the request has
    /// no `Authorization: Bearer` header. For browser apps whose session token
    /// is an httpOnly cookie set by the API, which script cannot copy into a
    /// header.
    ///
    /// A cookie is sent by the browser on its own, so a token read from one is
    /// an ambient credential: pair it with `SameSite` cookies or CSRF defences
    /// upstream (see SECURITY.md). Empty by default — only the header is read.
    #[serde(default)]
    pub token_cookies: Vec<String>,
}

/// Credential for service-to-service callers on the `machine` tier.
///
/// These callers are other systems, not people: there is no user token, only a
/// shared secret. Restricting *which* systems may reach the internal listener
/// is a network concern and belongs on that listener's ingress, not here.
#[derive(Clone, Deserialize, JsonSchema)]
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

/// Keys every caller of the public listener must present.
///
/// ```yaml
/// auth:
///   client_keys:
///     header: x-client-key
///     forward_as: x-client-id
///     keys:
///       storefront: ${STOREFRONT_CLIENT_KEY}
///       mobile: ${MOBILE_CLIENT_KEY}
/// ```
///
/// Configuring this turns the requirement on for *every* route on the public
/// listener, whatever its group: a key is checked before any token is read.
/// The health path is never keyed, and a route opts out only by saying so
/// (`client_key: false`) — for a caller that cannot send one, such as a payment
/// provider's webhook. The internal listener keeps the machine credential.
///
/// Unlike the machine credential, these are checked on the public listener, so
/// anything that can reach the gateway can try to guess one. That is why they
/// have a minimum length and why the check runs after the IP rate limit.
///
/// A key that a browser sends is readable by anyone who opens that page. It
/// tells honest clients apart and keeps out scanners that do not have it; it is
/// not a secret from a determined visitor, and user authorization still belongs
/// to the user's token.
#[derive(Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientKeysConfig {
    /// Header the caller presents its key in. Removed before the request is
    /// proxied, so an upstream never sees a client key.
    #[serde(default = "default_client_key_header")]
    pub header: String,
    /// Header that tells the upstream which client called, set to the key's id.
    /// A client-supplied copy is always removed, including on exempt routes.
    /// Unset, the upstream is not told.
    #[serde(default)]
    pub forward_as: Option<String>,
    /// Key id → secret. The id names the caller in logs, in `forward_as` and in
    /// `key: identity` rate limits. Several keys may be live at once, which is
    /// how a key is rotated: add the new one, move callers over, remove the old.
    pub keys: BTreeMap<String, String>,
    /// Path prefixes that never need a key, matched on segment boundaries the
    /// same way `routes.internal` is: `/webhooks` covers `/webhooks/xendit` but
    /// not `/webhooksx`.
    #[serde(default)]
    pub exempt: Vec<String>,
    /// Route groups whose routes never need a key: `public`, `optional` or
    /// `authenticated`.
    #[serde(default)]
    pub exempt_groups: Vec<String>,
}

/// Hand-written for the same reason as [`MachineConfig`]: every value in
/// `keys` is a credential. The ids are safe to print, and useful.
impl std::fmt::Debug for ClientKeysConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: BTreeMap<&str, Redacted> = self
            .keys
            .iter()
            .map(|(id, secret)| (id.as_str(), Redacted(secret.len())))
            .collect();
        f.debug_struct("ClientKeysConfig")
            .field("header", &self.header)
            .field("forward_as", &self.forward_as)
            .field("keys", &keys)
            .field("exempt", &self.exempt)
            .field("exempt_groups", &self.exempt_groups)
            .finish()
    }
}

fn default_client_key_header() -> String {
    "x-client-key".into()
}

/// Shorter keys are refused at startup. Client keys are checked on the public
/// listener, so their only protection against guessing is their length.
pub const MIN_CLIENT_KEY_LEN: usize = 16;

/// A client key, resolved for the request path.
///
/// Held as a SHA-256 digest, not as the key. Comparing two 32-byte digests
/// takes the same time whatever the keys' lengths, where comparing the keys
/// themselves stops early on a length mismatch and tells a guesser how long a
/// key is.
#[derive(Clone)]
pub struct ClientKey {
    pub id: String,
    pub digest: [u8; 32],
}

impl ClientKey {
    pub fn digest_of(key: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(ring::digest::digest(&ring::digest::SHA256, key).as_ref());
        out
    }

    /// Whether `presented` is this key, in constant time.
    pub fn matches(&self, presented_digest: &[u8; 32]) -> bool {
        use subtle::ConstantTimeEq;
        presented_digest.ct_eq(&self.digest).unwrap_u8() == 1
    }
}

impl std::fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKey")
            .field("id", &self.id)
            .field("digest", &"<redacted>")
            .finish()
    }
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
#[derive(Debug, Clone, Deserialize, JsonSchema)]
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
    #[schemars(with = "String")]
    pub clock_skew: Duration,
    /// Floor on how long fetched keys are cached, whatever the issuer's
    /// `Cache-Control` says.
    #[serde(with = "humantime_serde", default = "d300")]
    #[schemars(with = "String")]
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

#[derive(Debug, Clone, Deserialize, JsonSchema)]
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
    #[schemars(with = "String")]
    pub clock_skew: Duration,
    /// Floor on how long fetched signing certificates are cached, regardless of
    /// the upstream `Cache-Control` header.
    #[serde(with = "humantime_serde", default = "d300")]
    #[schemars(with = "String")]
    pub min_cert_ttl: Duration,
}

fn default_certs_url() -> String {
    "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
        .to_string()
}

// ---------------------------------------------------------- header policies

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
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

#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RejectConfig {
    /// Headers that cause an immediate 403 when a client sends them. Use for
    /// credentials and identity assertions the gateway produces itself.
    #[serde(default)]
    pub client_headers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ForwardMode {
    /// Drop every client header except those listed. The safe default: a header
    /// an upstream trusts can never arrive just because a client sent it.
    Allowlist,
    /// Relay client headers untouched apart from explicit strips.
    Passthrough,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
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
    /// Socket peers allowed to supply the trusted part of X-Forwarded-For.
    /// Required whenever a proxy hop is trusted; use IPs or CIDR ranges.
    #[serde(default)]
    pub trusted_proxy_ips: Vec<String>,
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
            trusted_proxy_ips: Vec::new(),
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
#[derive(Debug, Clone, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, JsonSchema)]
#[schemars(with = "schema::Claim")]
pub struct ClaimMapping {
    /// Dotted claim path, e.g. `company.id`.
    pub claim: String,
    /// Emitted when the claim is present but JSON `null`. Without it, a null
    /// claim is treated like an absent one and no header is set.
    pub when_null: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ClaimDetails {
    claim: String,
    #[serde(default)]
    when_null: Option<String>,
}

impl<'de> Deserialize<'de> for ClaimMapping {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
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
                let long =
                    ClaimDetails::deserialize(serde::de::value::MapAccessDeserializer::new(m))?;
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
#[derive(Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityTokenConfig {
    #[serde(default = "default_token_header")]
    pub header: String,
    /// HS256 signing secret. Keep it out of the file itself: `${SECRET}`.
    pub secret: String,
    #[serde(with = "humantime_serde", default = "d60")]
    #[schemars(with = "String")]
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
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoutesConfig {
    /// Load the groups below from this file instead of from this document.
    #[serde(default)]
    pub file: Option<String>,
    /// How often to re-read `file`. A ConfigMap update shows up as a changed
    /// mtime, so this is also how long a route change takes to land.
    #[serde(with = "humantime_serde", default = "d15")]
    #[schemars(with = "String")]
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
    pub trusted_proxy_ips: Vec<ipnet::IpNet>,
    pub upstreams: HashMap<String, UpstreamConfig>,
    pub injected_headers: Vec<(String, String)>,
    pub firebase_project_ids: Vec<String>,
    /// HS256 secret for identity-token minting.
    pub identity_secret: Option<Vec<u8>>,
    /// Caller credential for the machine tier.
    pub machine_secret: Option<String>,
    /// Injection set for the internal listener.
    pub machine_injected_headers: Vec<(String, String)>,
    /// `auth.client_keys.header`, lowercased. `None` when client keys are not configured.
    pub client_key_header: Option<String>,
    /// `auth.client_keys.forward_as`, lowercased.
    pub client_key_forward_as: Option<String>,
    /// Every client key, checked in full on each request that needs one.
    pub client_keys: Vec<ClientKey>,
    /// `auth.client_keys.exempt`, normalized like the deny-list.
    pub client_key_exempt: Vec<String>,
    /// `auth.client_keys.exempt_groups`.
    pub client_key_exempt_groups: Vec<String>,
    /// `server.mounts`, normalized and sorted longest-first.
    pub base_paths: Vec<String>,
    /// Compiled cross-origin policy.
    pub cors: Option<crate::cors::Cors>,
    /// Environment variables the document referenced, for `validate` output.
    pub referenced_env: Vec<String>,
    /// Those that fell back to a default — the ones that differ between a
    /// laptop and a cluster.
    pub defaulted_env: Vec<String>,
    /// Those filled with a placeholder under `validate --allow-unset`. Non-empty
    /// means part of this document was checked against a value nobody will ever
    /// run with, so `validate` says so rather than reporting a clean pass.
    pub placeheld_env: Vec<String>,
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
        Self::load_with_fallback(path, None)
    }

    /// As [`Self::load`], but a variable that is unset and has no default is
    /// filled with `fallback` instead of failing.
    ///
    /// Only `validate --allow-unset` passes a value here. Serving paths pass
    /// `None` so an unset credential or upstream stays a startup failure.
    pub fn load_with_fallback(
        path: &str,
        fallback: Option<&dyn Fn(&str) -> String>,
    ) -> Result<(Self, Interpolated), ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_string(),
            source,
        })?;
        let (mut cfg, expanded) = Self::parse_with_fallback(path, &text, fallback)?;
        cfg.resolve_route_file_against(path);
        Ok((cfg, expanded))
    }

    /// Resolve a relative route file against the document that names it.
    /// Looking in the working directory first could silently load a different
    /// route table (and therefore a different authentication policy).
    pub(crate) fn resolve_route_file_against(&mut self, config_path: &str) {
        let Some(file) = self.routes.file.as_ref() else {
            return;
        };
        if Path::new(file).is_absolute() {
            return;
        }
        let Some(dir) = Path::new(config_path).parent() else {
            return;
        };
        let candidate = dir.join(file);
        if let Some(p) = candidate.to_str() {
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
        Self::from_expanded(path, expanded)
    }

    /// As [`Self::parse`], but a variable that is unset and has no default is
    /// filled with `fallback` rather than being an error. See
    /// [`interpolate::interpolate_with_fallback`] for why this is offered to
    /// `validate` alone.
    pub fn parse_with_fallback(
        path: &str,
        text: &str,
        fallback: Option<&dyn Fn(&str) -> String>,
    ) -> Result<(Self, Interpolated), ConfigError> {
        let expanded =
            interpolate::interpolate_env_with_fallback(text, fallback).map_err(|error| {
                ConfigError::Interpolate {
                    path: path.to_string(),
                    error,
                }
            })?;
        Self::from_expanded(path, expanded)
    }

    /// Parse an already-expanded document. The expansion strategy is the only
    /// thing that differs between the entry points above; everything from the
    /// YAML parse onward is shared.
    fn from_expanded(
        path: &str,
        expanded: Interpolated,
    ) -> Result<(Self, Interpolated), ConfigError> {
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
        if self
            .defaults
            .rate_limit
            .as_ref()
            .is_some_and(|rate| rate.requests == 0)
        {
            return Err(ConfigError::invalid(
                "defaults.rate_limit.requests must be greater than zero",
            ));
        }
        if self.timeouts.connect.is_zero() || self.timeouts.downstream_read.is_zero() {
            return Err(ConfigError::invalid(
                "timeouts.connect and timeouts.downstream_read must be greater than zero",
            ));
        }
        let trusted_proxy_ips: Vec<ipnet::IpNet> = self
            .forward
            .trusted_proxy_ips
            .iter()
            .map(|entry| {
                entry.parse().map_err(|_| {
                    ConfigError::invalid(format!(
                        "forward.trusted_proxy_ips: `{entry}` is not an IP address or CIDR range"
                    ))
                })
            })
            .collect::<Result<_, _>>()?;
        if self.forward.trusted_proxies > 0 && trusted_proxy_ips.is_empty() {
            return Err(ConfigError::invalid(
                "forward.trusted_proxies requires forward.trusted_proxy_ips; otherwise a direct caller could forge the proxy's address header",
            ));
        }
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
        let resolved_keys = match &self.auth.client_keys {
            Some(ck) => Some(resolve_client_keys(
                ck,
                &self.reject.client_headers,
                &self.gateway_owned_headers(),
            )?),
            None => None,
        };
        let (
            client_key_header,
            client_key_forward_as,
            client_keys,
            client_key_exempt,
            client_key_exempt_groups,
        ) = match resolved_keys {
            Some(r) => (
                Some(r.header),
                r.forward_as,
                r.keys,
                r.exempt,
                r.exempt_groups,
            ),
            None => (None, None, Vec::new(), Vec::new(), Vec::new()),
        };

        validate_token_cookies(&self.auth)?;

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
            trusted_proxy_ips,
            upstreams,
            injected_headers,
            firebase_project_ids,
            identity_secret,
            machine_secret,
            machine_injected_headers,
            client_key_header,
            client_key_forward_as,
            client_keys,
            client_key_exempt,
            client_key_exempt_groups,
            base_paths,
            referenced_env: expanded.referenced.clone(),
            defaulted_env: expanded.defaulted.clone(),
            placeheld_env: expanded.placeheld.clone(),
        })
    }
}

/// `auth.token_cookies`: names a browser could actually send, each once, and
/// only where something verifies tokens — otherwise the setting would be read
/// by nothing and look like protection.
fn validate_token_cookies(auth: &AuthConfig) -> Result<(), ConfigError> {
    if auth.token_cookies.is_empty() {
        return Ok(());
    }
    if auth.jwt.is_empty() && auth.firebase.is_none() {
        return Err(ConfigError::invalid(
            "auth.token_cookies is set but no auth.jwt or auth.firebase verifies tokens",
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for name in &auth.token_cookies {
        if !is_cookie_name(name) {
            return Err(ConfigError::invalid(format!(
                "auth.token_cookies: `{name}` is not a valid cookie name"
            )));
        }
        // Cookie names are case-sensitive, so this is an exact comparison.
        if !seen.insert(name.as_str()) {
            return Err(ConfigError::invalid(format!(
                "auth.token_cookies: `{name}` is listed twice"
            )));
        }
    }
    Ok(())
}

/// An RFC 6265 `cookie-name`: an RFC 7230 token, i.e. visible ASCII without
/// separators.
fn is_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?={}".contains(&b))
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

/// Headers a client key may not be read from or forwarded as. The gateway reads
/// or rewrites each of these itself, so sharing a name would either leak the key
/// onward or let it be confused with another credential.
const RESERVED_CLIENT_KEY_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "host",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "forwarded",
    "x-real-ip",
    "x-request-id",
    "traceparent",
    "tracestate",
    // Framing and hop-by-hop: stripping or writing one of these changes how
    // the request itself is read, not just what it says.
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
    "expect",
];

/// Validates `auth.client_keys` and precomputes what the request path needs:
/// the lowercased header names and the keys as bytes.
struct ResolvedClientKeys {
    header: String,
    forward_as: Option<String>,
    keys: Vec<ClientKey>,
    exempt: Vec<String>,
    exempt_groups: Vec<String>,
}

/// Groups `exempt_groups` may name. `machine` is absent on purpose: its routes
/// are on the internal listener, where client keys are never checked.
const EXEMPTIBLE_GROUPS: &[&str] = &["public", "optional", "authenticated"];

impl GatewayConfig {
    /// Every header the gateway itself writes to an upstream request, lowercased:
    /// identity headers, the identity token, injected credentials and the
    /// machine credential names. A client key header or `forward_as` sharing one
    /// of these would overwrite a verified value, or be overwritten by it.
    fn gateway_owned_headers(&self) -> Vec<String> {
        let id = &self.identity;
        let mut owned: Vec<String> = [&id.subject_header, &id.issuer_header, &id.claims_header]
            .into_iter()
            .cloned()
            .chain(id.claims.keys().cloned())
            .chain(id.token.iter().map(|t| t.header.clone()))
            .chain(self.inject.headers.keys().cloned())
            .chain(self.inject.machine.keys().cloned())
            .chain(
                self.auth
                    .machine
                    .iter()
                    .flat_map(|m| m.headers.iter().cloned()),
            )
            .map(|h| h.trim().to_ascii_lowercase())
            .collect();
        owned.sort();
        owned.dedup();
        owned
    }
}

fn resolve_client_keys(
    ck: &ClientKeysConfig,
    rejected: &[String],
    owned: &[String],
) -> Result<ResolvedClientKeys, ConfigError> {
    let header_name = |field: &str, raw: &str| -> Result<String, ConfigError> {
        let name = raw.trim().to_ascii_lowercase();
        if http::HeaderName::from_bytes(name.as_bytes()).is_err() {
            return Err(ConfigError::invalid(format!(
                "auth.client_keys.{field}: `{raw}` is not a valid header name"
            )));
        }
        if RESERVED_CLIENT_KEY_HEADERS.contains(&name.as_str()) {
            return Err(ConfigError::invalid(format!(
                "auth.client_keys.{field}: `{name}` is a header the gateway reads or sets \
                 itself; use a dedicated name such as `x-client-key`"
            )));
        }
        if owned.contains(&name) {
            return Err(ConfigError::invalid(format!(
                "auth.client_keys.{field}: `{name}` is already an identity, injected or machine \
                 header in this configuration; sharing it would let a client key overwrite a \
                 verified value, or be overwritten by one"
            )));
        }
        Ok(name)
    };

    let header = header_name("header", &ck.header)?;
    if rejected.iter().any(|r| r.eq_ignore_ascii_case(&header)) {
        return Err(ConfigError::invalid(format!(
            "auth.client_keys.header `{header}` is also listed in reject.client_headers, which \
             refuses any request carrying it; every keyed request would be a 403"
        )));
    }

    let forward_as = match &ck.forward_as {
        Some(raw) => {
            let name = header_name("forward_as", raw)?;
            if name == header {
                return Err(ConfigError::invalid(format!(
                    "auth.client_keys.forward_as is the same header as auth.client_keys.header \
                     (`{name}`); the upstream would receive the key's id where the key was"
                )));
            }
            Some(name)
        }
        None => None,
    };

    if ck.keys.is_empty() {
        return Err(ConfigError::invalid(
            "auth.client_keys.keys is empty; every keyed route would refuse every request",
        ));
    }
    let mut keys: Vec<ClientKey> = Vec::with_capacity(ck.keys.len());
    for (id, secret) in &ck.keys {
        // The id becomes a header value (`forward_as`) and a rate-limit key, so
        // it is held to a plain token alphabet.
        let id_ok = !id.is_empty()
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
        if !id_ok {
            return Err(ConfigError::invalid(format!(
                "auth.client_keys.keys: id `{id}` must be non-empty and use only letters, \
                 digits, `-`, `_` and `.`"
            )));
        }
        // A trailing newline from `echo secret > file` or a padded variable
        // would otherwise produce a key no client ever sends.
        if secret.trim() != secret {
            return Err(ConfigError::invalid(format!(
                "auth.client_keys.keys.{id}: the key has leading or trailing whitespace"
            )));
        }
        if secret.len() < MIN_CLIENT_KEY_LEN {
            return Err(ConfigError::invalid(format!(
                "auth.client_keys.keys.{id}: the key is {} bytes; at least {MIN_CLIENT_KEY_LEN} \
                 are required, because anything that can reach the public listener can try to \
                 guess it",
                secret.len()
            )));
        }
        let digest = ClientKey::digest_of(secret.as_bytes());
        if let Some(other) = keys.iter().find(|k| k.digest == digest) {
            return Err(ConfigError::invalid(format!(
                "auth.client_keys.keys: `{id}` and `{}` have the same key, so the gateway \
                 could not tell which client called",
                other.id
            )));
        }
        keys.push(ClientKey {
            id: id.clone(),
            digest,
        });
    }

    let mut exempt = Vec::with_capacity(ck.exempt.len());
    for raw in &ck.exempt {
        let prefix = crate::path::normalize_proxy_path(raw.trim());
        if prefix.is_empty() {
            return Err(ConfigError::invalid(format!(
                "auth.client_keys.exempt: `{raw}` is empty; name the path prefix to exempt"
            )));
        }
        // Compared with the canonical request path, so an entry that does not
        // canonicalize to itself (`a//b`, `%2e`, `..`) could never match and
        // would leave the route it was meant for demanding a key.
        if crate::path::canonicalize_proxy_path(prefix).as_deref() != Some(prefix) {
            return Err(ConfigError::invalid(format!(
                "auth.client_keys.exempt: `{raw}` is not a canonical path; write it as the \
                 gateway sees it — decoded, without empty or dot segments, relative to any \
                 `server.mounts`"
            )));
        }
        exempt.push(prefix.to_string());
    }

    let mut exempt_groups = Vec::with_capacity(ck.exempt_groups.len());
    for raw in &ck.exempt_groups {
        let group = raw.trim().to_ascii_lowercase();
        if group == "machine" {
            return Err(ConfigError::invalid(
                "auth.client_keys.exempt_groups: `machine` routes are on the internal listener, \
                 where client keys are never checked; there is nothing to exempt",
            ));
        }
        if !EXEMPTIBLE_GROUPS.contains(&group.as_str()) {
            return Err(ConfigError::invalid(format!(
                "auth.client_keys.exempt_groups: `{raw}` is not a route group; use one of {}",
                EXEMPTIBLE_GROUPS.join(", ")
            )));
        }
        exempt_groups.push(group);
    }

    Ok(ResolvedClientKeys {
        header,
        forward_as,
        keys,
        exempt,
        exempt_groups,
    })
}

/// Whether a request to a route needs a client key, and if not, why not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientKeyRule {
    /// `auth.client_keys` is not configured, or the route is on the internal
    /// listener.
    Off,
    Required,
    Exempt(ClientKeyExemption),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientKeyExemption {
    /// `client_key: false` on the route.
    Route,
    /// Under one of `auth.client_keys.exempt`.
    Prefix(String),
    /// The route's group is in `auth.client_keys.exempt_groups`.
    Group(String),
}

impl ClientKeyExemption {
    pub fn describe(&self) -> String {
        match self {
            Self::Route => "client_key: false on the route".into(),
            Self::Prefix(p) => format!("under auth.client_keys.exempt `/{p}`"),
            Self::Group(g) => format!("group `{g}` is in auth.client_keys.exempt_groups"),
        }
    }
}

impl ResolvedConfig {
    /// The one place that decides whether a request needs a client key. The
    /// proxy, `explain` and `lagos test` all ask here, so they cannot disagree.
    ///
    /// `path` is the canonical request path, the one the deny-list sees.
    pub fn client_key_rule(&self, route: &RouteConfig, path: &str) -> ClientKeyRule {
        if self.client_key_header.is_none() || route.auth.is_machine() {
            return ClientKeyRule::Off;
        }
        if route.client_key == Some(false) {
            return ClientKeyRule::Exempt(ClientKeyExemption::Route);
        }
        let path = crate::path::normalize_proxy_path(path);
        if let Some(prefix) = self
            .client_key_exempt
            .iter()
            .find(|p| crate::routes::under_prefix(path, p))
        {
            return ClientKeyRule::Exempt(ClientKeyExemption::Prefix(prefix.clone()));
        }
        let group = route.auth.group();
        if self.client_key_exempt_groups.iter().any(|g| g == group) {
            return ClientKeyRule::Exempt(ClientKeyExemption::Group(group.to_string()));
        }
        ClientKeyRule::Required
    }
}

fn lower_pairs(map: &BTreeMap<String, String>) -> Vec<(String, String)> {
    map.iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect()
}

/// Routes with the same prefix cannot depend on declaration order for a
/// security decision. A host-specific route and a catch-all on the same tier
/// are the deliberate exception: host specificity decides which one wins.
fn conflicting_routes(a: &RouteConfig, b: &RouteConfig) -> bool {
    if a.prefix != b.prefix || a.auth.is_machine() != b.auth.is_machine() {
        return false;
    }
    if a.auth == b.auth && a.hosts.is_empty() != b.hosts.is_empty() {
        return false;
    }
    let methods_overlap = a.methods.is_empty()
        || b.methods.is_empty()
        || a.methods.iter().any(|method| b.methods.contains(method));
    let hosts_overlap = a.hosts.is_empty()
        || b.hosts.is_empty()
        || a.hosts
            .iter()
            .any(|host| b.hosts.iter().any(|other| host.overlaps(other)));
    methods_overlap && hosts_overlap
}

impl ResolvedConfig {
    /// Only an allowlisted socket peer may vouch for forwarded address hops.
    pub fn trusted_proxy_depth(&self, peer: Option<&str>, configured: usize) -> usize {
        let Some(ip) = peer.and_then(|p| p.parse::<std::net::IpAddr>().ok()) else {
            return 0;
        };
        if self
            .trusted_proxy_ips
            .iter()
            .any(|range| range.contains(&ip))
        {
            configured
        } else {
            0
        }
    }

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
            if let Some(limit) = &r.rate_limit
                && matches!(limit.key, RateLimitKey::Ip)
                && limit.trusted_proxies > 0
                && self.trusted_proxy_ips.is_empty()
            {
                return Err(ConfigError::invalid(format!(
                    "route `{}` trusts X-Forwarded-For for its IP limit but forward.trusted_proxy_ips is empty",
                    r.id
                )));
            }
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

        for (index, route) in routes.iter().enumerate() {
            for other in routes.iter().skip(index + 1) {
                if conflicting_routes(route, other) {
                    return Err(ConfigError::invalid(format!(
                        "routes `{}` ({}) and `{}` ({}) both match prefix `{}` for at least one \
                         host and method. Routes on the same listener must not depend on \
                         declaration order for authorization.",
                        route.id,
                        route.auth.group(),
                        other.id,
                        other.auth.group(),
                        route.prefix,
                    )));
                }
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

        // A `client_key` that cannot take effect reads like a control and does
        // nothing — `true` would look enforced, `false` would look exempted.
        // Refuse it either way so nobody relies on it.
        for r in routes.iter().filter(|r| r.client_key.is_some()) {
            if r.auth.is_machine() {
                return Err(ConfigError::invalid(format!(
                    "route `{}` is in the `machine` group and sets `client_key`. Client keys \
                     are checked on the public listener only; the machine credential still \
                     applies",
                    r.id
                )));
            }
            if self.raw.auth.client_keys.is_none() {
                return Err(ConfigError::invalid(format!(
                    "route `{}` sets `client_key` but `auth.client_keys` is not configured, so \
                     no route needs a key and the field would have no effect",
                    r.id
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
    fn trusted_proxy_hops_require_allowlisted_socket_peers() {
        let missing = format!("forward:\n  trusted_proxies: 1\n{MINIMAL}");
        assert!(parse(&missing).is_err());

        let allowed = format!(
            "forward:\n  trusted_proxies: 1\n  trusted_proxy_ips: [10.0.0.0/8, '2001:db8::/32']\n{MINIMAL}"
        );
        let cfg = parse(&allowed).expect("valid proxy CIDRs");
        assert_eq!(cfg.trusted_proxy_depth(Some("10.1.2.3"), 1), 1);
        assert_eq!(cfg.trusted_proxy_depth(Some("2001:db8::1"), 1), 1);
        assert_eq!(cfg.trusted_proxy_depth(Some("203.0.113.7"), 1), 0);
        assert_eq!(cfg.trusted_proxy_depth(None, 1), 0);
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
    fn a_relative_route_file_stays_with_its_config_directory() {
        let (mut cfg, _) = GatewayConfig::parse(
            "test.yml",
            "upstreams: {u: http://u:1}\nroutes: {file: routes.yml}\n",
        )
        .expect("config parses");
        cfg.resolve_route_file_against("/etc/lagos/gateway.yml");
        assert_eq!(cfg.routes.file.as_deref(), Some("/etc/lagos/routes.yml"));

        cfg.routes.file = Some("/custom/routes.yml".into());
        cfg.resolve_route_file_against("/etc/lagos/gateway.yml");
        assert_eq!(cfg.routes.file.as_deref(), Some("/custom/routes.yml"));
    }

    #[test]
    fn same_prefix_on_public_and_authenticated_tiers_is_refused() {
        let err = table(
            "upstreams: {u: http://u:1}\nroutes:\n  public:\n    - {id: open, prefix: /secret, upstream: u}\n  authenticated:\n    - {id: protected, prefix: /secret, upstream: u}\n",
        )
        .expect_err("public route would shadow authentication");
        assert!(err.to_string().contains("both match prefix"), "{err}");
    }

    #[test]
    fn overlapping_host_patterns_at_one_prefix_are_refused() {
        let err = table(
            "upstreams: {u: http://u:1}\nroutes:\n  public:\n    - {id: wildcard, host: '*.example.com', prefix: /api, upstream: u}\n    - {id: exact, host: foo.example.com, prefix: /api, upstream: u}\n",
        )
        .expect_err("both routes match foo.example.com");
        assert!(err.to_string().contains("both match prefix"), "{err}");
    }

    #[test]
    fn host_specific_override_and_disjoint_methods_remain_valid() {
        table(
            "upstreams: {u: http://u:1}\nroutes:\n  public:\n    - {id: any, prefix: /api, upstream: u, methods: [GET]}\n    - {id: specific, host: api.example.com, prefix: /api, upstream: u, methods: [GET]}\n    - {id: posting, prefix: /api, upstream: u, methods: [POST]}\n",
        )
        .expect("specific host overrides catch-all; methods do not overlap");
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod client_key_tests {
    use super::*;

    const KEY_A: &str = "storefront-key-0123456789";
    const KEY_B: &str = "admin-web-key-0123456789";

    /// A gateway with client keys on and one route per group. `extra` is
    /// spliced into `auth.client_keys`, `routes` replaces the route table.
    fn doc(extra: &str, routes: &str) -> String {
        format!(
            r#"
server: {{ internal_listen: 127.0.0.1:8081 }}
upstreams: {{ api: http://api:8080 }}
auth:
  machine: {{ secret: machine-secret }}
  client_keys:
    keys: {{ storefront: {KEY_A}, admin-web: {KEY_B} }}
{extra}
routes:
{routes}
"#
        )
    }

    const ROUTES: &str = r#"
  public:
    - { id: books, prefix: books, upstream: api }
    - { id: webhooks, prefix: webhooks, upstream: api }
    - { id: xendit, prefix: pay/xendit, upstream: api, client_key: false }
  optional:
    - { id: catalog, prefix: catalog, upstream: api }
  authenticated:
    - { id: orders, prefix: orders, upstream: api }
  machine:
    - { id: sync, prefix: sync, upstream: api }
"#;

    fn load(text: &str) -> Result<(ResolvedConfig, crate::routes::RouteTable), ConfigError> {
        let (cfg, expanded) = GatewayConfig::parse("test.yml", text)?;
        let resolved = cfg.resolve(&expanded)?;
        let table = crate::routes::RouteTable::build(resolved.raw.routes.groups());
        resolved.validate_table(&table)?;
        Ok((resolved, table))
    }

    fn rule(cfg: &ResolvedConfig, table: &crate::routes::RouteTable, path: &str) -> ClientKeyRule {
        let route = table
            .routes()
            .iter()
            .find(|r| crate::routes::under_prefix(path, &r.prefix))
            .unwrap();
        cfg.client_key_rule(route, path)
    }

    fn refused(text: &str, needle: &str) {
        let err = load(text)
            .expect_err("configuration should be refused")
            .to_string();
        assert!(err.contains(needle), "`{needle}` not in: {err}");
    }

    #[test]
    fn keys_resolve_with_default_header_and_ids() {
        let (cfg, _) = load(&doc("", ROUTES)).unwrap();
        assert_eq!(cfg.client_key_header.as_deref(), Some("x-client-key"));
        assert_eq!(cfg.client_key_forward_as, None);
        let ids: Vec<_> = cfg.client_keys.iter().map(|k| k.id.as_str()).collect();
        assert_eq!(ids, ["admin-web", "storefront"]);
    }

    #[test]
    fn every_public_listener_group_requires_a_key_by_default() {
        let (cfg, table) = load(&doc("", ROUTES)).unwrap();
        for path in ["books/1", "catalog", "orders/9"] {
            assert_eq!(rule(&cfg, &table, path), ClientKeyRule::Required, "{path}");
        }
    }

    #[test]
    fn machine_routes_are_never_keyed() {
        let (cfg, table) = load(&doc("", ROUTES)).unwrap();
        assert_eq!(rule(&cfg, &table, "sync/run"), ClientKeyRule::Off);
    }

    #[test]
    fn nothing_is_keyed_without_client_keys() {
        let (cfg, table) = load(
            "upstreams: {api: http://api:8080}\nroutes:\n  public:\n    - {id: books, prefix: books, upstream: api}\n",
        )
        .unwrap();
        assert!(cfg.client_key_header.is_none());
        assert_eq!(rule(&cfg, &table, "books/1"), ClientKeyRule::Off);
    }

    #[test]
    fn a_route_can_opt_out() {
        let (cfg, table) = load(&doc("", ROUTES)).unwrap();
        assert_eq!(
            rule(&cfg, &table, "pay/xendit/callback"),
            ClientKeyRule::Exempt(ClientKeyExemption::Route)
        );
    }

    #[test]
    fn exempt_prefixes_match_on_segment_boundaries() {
        let routes = ROUTES.replace(
            "    - { id: webhooks, prefix: webhooks, upstream: api }\n",
            "    - { id: webhooks, prefix: webhooks, upstream: api }\n    - { id: webhooksx, prefix: webhooksx, upstream: api }\n",
        );
        let (cfg, table) = load(&doc("    exempt: [/webhooks/]", &routes)).unwrap();
        assert_eq!(
            rule(&cfg, &table, "webhooks/xendit"),
            ClientKeyRule::Exempt(ClientKeyExemption::Prefix("webhooks".into()))
        );
        assert_eq!(
            rule(&cfg, &table, "webhooks"),
            ClientKeyRule::Exempt(ClientKeyExemption::Prefix("webhooks".into()))
        );
        assert_eq!(rule(&cfg, &table, "webhooksx/1"), ClientKeyRule::Required);
    }

    #[test]
    fn an_exempt_prefix_can_sit_beneath_a_route() {
        let (cfg, table) = load(&doc("    exempt: [books/covers]", ROUTES)).unwrap();
        assert_eq!(
            rule(&cfg, &table, "books/covers/1.jpg"),
            ClientKeyRule::Exempt(ClientKeyExemption::Prefix("books/covers".into()))
        );
        assert_eq!(rule(&cfg, &table, "books/1"), ClientKeyRule::Required);
    }

    #[test]
    fn exempt_groups_cover_every_route_in_them() {
        let (cfg, table) = load(&doc("    exempt_groups: [Optional]", ROUTES)).unwrap();
        assert_eq!(
            rule(&cfg, &table, "catalog"),
            ClientKeyRule::Exempt(ClientKeyExemption::Group("optional".into()))
        );
        assert_eq!(rule(&cfg, &table, "books/1"), ClientKeyRule::Required);
        assert_eq!(rule(&cfg, &table, "orders/1"), ClientKeyRule::Required);
    }

    #[test]
    fn the_route_opt_out_is_reported_before_any_list() {
        let (cfg, table) = load(&doc(
            "    exempt: [pay]\n    exempt_groups: [public]",
            ROUTES,
        ))
        .unwrap();
        assert_eq!(
            rule(&cfg, &table, "pay/xendit"),
            ClientKeyRule::Exempt(ClientKeyExemption::Route)
        );
    }

    #[test]
    fn short_keys_are_refused() {
        refused(
            &doc("", ROUTES).replace(KEY_A, "short"),
            "at least 16 are required",
        );
    }

    #[test]
    fn padded_keys_are_refused() {
        refused(
            &doc("", ROUTES).replace(KEY_A, &format!("\"{KEY_A} \"")),
            "leading or trailing whitespace",
        );
    }

    #[test]
    fn two_ids_sharing_a_key_are_refused() {
        refused(&doc("", ROUTES).replace(KEY_B, KEY_A), "have the same key");
    }

    #[test]
    fn an_empty_key_set_is_refused() {
        refused(
            &doc("", ROUTES).replace(
                &format!("{{ storefront: {KEY_A}, admin-web: {KEY_B} }}"),
                "{}",
            ),
            "keys is empty",
        );
    }

    #[test]
    fn ids_are_held_to_a_header_safe_alphabet() {
        refused(
            &doc("", ROUTES).replace("admin-web:", "\"admin web\":"),
            "must be non-empty and use only",
        );
    }

    #[test]
    fn reserved_header_names_are_refused() {
        refused(
            &doc("    header: Authorization", ROUTES),
            "reads or sets itself",
        );
        refused(
            &doc("    forward_as: x-request-id", ROUTES),
            "reads or sets itself",
        );
    }

    #[test]
    fn forward_as_must_differ_from_the_key_header() {
        refused(
            &doc("    header: x-reko-key\n    forward_as: X-Reko-Key", ROUTES),
            "same header",
        );
    }

    #[test]
    fn a_key_header_on_the_reject_list_is_refused() {
        let text = doc("", ROUTES) + "reject:\n  client_headers: [X-Client-Key]\n";
        refused(&text, "reject.client_headers");
    }

    #[test]
    fn exempting_machine_or_unknown_groups_is_refused() {
        refused(
            &doc("    exempt_groups: [machine]", ROUTES),
            "internal listener",
        );
        refused(
            &doc("    exempt_groups: [admins]", ROUTES),
            "is not a route group",
        );
    }

    #[test]
    fn an_empty_exempt_prefix_is_refused() {
        refused(&doc("    exempt: [/]", ROUTES), "is empty");
    }

    #[test]
    fn client_key_without_client_keys_is_refused_either_way() {
        for value in ["false", "true"] {
            refused(
                &format!(
                    "upstreams: {{api: http://api:8080}}\nroutes:\n  public:\n    - {{id: hooks, prefix: hooks, upstream: api, client_key: {value}}}\n"
                ),
                "would have no effect",
            );
        }
    }

    #[test]
    fn an_explicit_true_is_the_same_as_unset() {
        let routes = ROUTES.replace(
            "{ id: books, prefix: books, upstream: api }",
            "{ id: books, prefix: books, upstream: api, client_key: true }",
        );
        let (cfg, table) = load(&doc("", &routes)).unwrap();
        assert_eq!(rule(&cfg, &table, "books/1"), ClientKeyRule::Required);
    }

    #[test]
    fn headers_the_gateway_already_writes_are_refused() {
        // Identity: a key id must never be mistaken for a verified subject.
        refused(
            &doc("    forward_as: X-Auth-Subject", ROUTES),
            "already an identity",
        );
        let with_inject = doc("    header: x-api-key", ROUTES)
            + "inject:\n  headers:\n    x-api-key: upstream-secret\n";
        refused(&with_inject, "already an identity, injected or machine");
        // The machine credential names default to x-internal-api-key and x-api-key.
        refused(
            &doc("    forward_as: x-internal-api-key", ROUTES),
            "already an identity",
        );
    }

    #[test]
    fn framing_headers_are_refused() {
        for name in [
            "content-length",
            "transfer-encoding",
            "connection",
            "expect",
        ] {
            refused(
                &doc(&format!("    header: {name}"), ROUTES),
                "reads or sets itself",
            );
            refused(
                &doc(&format!("    forward_as: {name}"), ROUTES),
                "reads or sets itself",
            );
        }
    }

    #[test]
    fn a_non_canonical_exempt_prefix_is_refused() {
        for raw in ["hooks//x", "hooks/../books", "%68ooks"] {
            refused(
                &doc(&format!("    exempt: [\"{raw}\"]"), ROUTES),
                "not a canonical path",
            );
        }
    }

    #[test]
    fn keys_are_held_as_digests() {
        let (cfg, _) = load(&doc("", ROUTES)).unwrap();
        let storefront = cfg
            .client_keys
            .iter()
            .find(|k| k.id == "storefront")
            .unwrap();
        assert!(storefront.matches(&ClientKey::digest_of(KEY_A.as_bytes())));
        assert!(!storefront.matches(&ClientKey::digest_of(KEY_B.as_bytes())));
        assert!(!storefront.matches(&ClientKey::digest_of(&KEY_A.as_bytes()[..20])));
    }

    #[test]
    fn an_opt_out_on_a_machine_route_is_refused() {
        let routes = ROUTES.replace(
            "{ id: sync, prefix: sync, upstream: api }",
            "{ id: sync, prefix: sync, upstream: api, client_key: false }",
        );
        refused(&doc("", &routes), "machine credential still applies");
    }

    #[test]
    fn debug_output_never_contains_a_key() {
        let (cfg, _) = load(&doc("", ROUTES)).unwrap();
        let printed = format!("{cfg:?}");
        assert!(
            !printed.contains(KEY_A) && !printed.contains(KEY_B),
            "{printed}"
        );
        assert!(printed.contains("storefront"), "ids stay visible");
    }
}

#[cfg(test)]
mod token_cookie_tests {
    use super::*;

    const ISSUER: &str = "  jwt:\n    - { issuer: https://issuer.test, audience: [api] }\n";
    const ROUTES: &str = "upstreams: {api: http://api:8080}\nroutes:\n  optional:\n    - { id: books, prefix: books, upstream: api }\n";

    fn load(auth: &str) -> Result<ResolvedConfig, ConfigError> {
        let text = format!("auth:\n{auth}{ROUTES}");
        let (cfg, expanded) = GatewayConfig::parse("test.yml", &text)?;
        cfg.resolve(&expanded)
    }

    fn refused(auth: &str, needle: &str) {
        let err = load(auth)
            .expect_err("configuration should be refused")
            .to_string();
        assert!(err.contains(needle), "`{needle}` not in: {err}");
    }

    #[test]
    fn off_by_default() {
        let cfg = load(ISSUER).unwrap();
        assert!(cfg.raw.auth.token_cookies.is_empty());
    }

    #[test]
    fn names_are_kept_in_order() {
        let cfg = load(&format!(
            "{ISSUER}  token_cookies: [access_token, __Host-session]\n"
        ))
        .unwrap();
        assert_eq!(
            cfg.raw.auth.token_cookies,
            ["access_token", "__Host-session"]
        );
    }

    #[test]
    fn needs_something_that_verifies_tokens() {
        refused(
            "  token_cookies: [access_token]\n",
            "no auth.jwt or auth.firebase",
        );
    }

    #[test]
    fn invalid_names_are_refused() {
        for bad in ["\"\"", "\"a b\"", "\"a;b\"", "\"a=b\"", "\"a,b\""] {
            refused(
                &format!("{ISSUER}  token_cookies: [{bad}]\n"),
                "is not a valid cookie name",
            );
        }
    }

    #[test]
    fn a_name_listed_twice_is_refused() {
        refused(
            &format!("{ISSUER}  token_cookies: [access_token, access_token]\n"),
            "is listed twice",
        );
        // Case matters for cookie names, so these are two different cookies.
        assert!(load(&format!("{ISSUER}  token_cookies: [t, T]\n")).is_ok());
    }
}
