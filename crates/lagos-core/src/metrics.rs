//! Prometheus metrics.
//!
//! Exposed on a listener of their own, never on the traffic port:
//!
//! ```yaml
//! observability:
//!   metrics:
//!     listen: 0.0.0.0:9090
//! ```
//!
//! # Cardinality
//!
//! Every label here is bounded by *configuration*, never by request content. A
//! Prometheus label fed from a request is a memory-exhaustion bug with extra
//! steps: each distinct value allocates a permanent time series, so an attacker
//! who can invent label values can grow the process without bound.
//!
//! That rules out paths, request IDs, user IDs and token subjects — and it is
//! why [`normalize_method`] exists, since a client may send any method it likes.

use std::sync::OnceLock;

use prometheus::{
    HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, register_histogram_vec,
    register_int_counter_vec, register_int_gauge, register_int_gauge_vec,
};

/// Methods that may appear as a label. Anything else becomes `OTHER`, so a
/// client cannot mint time series by inventing verbs.
const KNOWN_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
];

/// Label used when no route matched. A literal beats an empty string, which
/// reads as a scrape bug.
const NO_ROUTE: &str = "-";

pub struct Metrics {
    requests: IntCounterVec,
    duration: HistogramVec,
    rejections: IntCounterVec,
    upstream_errors: IntCounterVec,
    retries: IntCounterVec,
    spans_dropped: prometheus::IntCounter,
    routes: IntGauge,
    backends: IntGaugeVec,
    circuit: IntGaugeVec,
    cache: IntCounterVec,
}

static METRICS: OnceLock<Metrics> = OnceLock::new();

/// The process-wide metrics, registered on first use.
///
/// Registration can only fail if a name is registered twice, which would be a
/// programming error rather than a runtime condition; the metrics are built
/// once and shared.
pub fn metrics() -> Option<&'static Metrics> {
    if METRICS.get().is_none() {
        let built = Metrics::build().ok()?;
        let _ = METRICS.set(built);
    }
    METRICS.get()
}

impl Metrics {
    fn build() -> prometheus::Result<Self> {
        Ok(Self {
            requests: register_int_counter_vec!(
                "gateway_requests_total",
                "Requests answered, by route, method and status.",
                &["route", "method", "status"]
            )?,
            duration: register_histogram_vec!(
                "gateway_request_duration_seconds",
                "End-to-end time to answer a request, including the upstream.",
                &["route"],
                // Tuned for an API gateway: sub-millisecond refusals through to
                // a slow upstream, rather than Prometheus' web-page defaults.
                vec![
                    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
                ]
            )?,
            rejections: register_int_counter_vec!(
                "gateway_rejections_total",
                "Requests the gateway refused itself, by event and reason.",
                &["event", "reason"]
            )?,
            upstream_errors: register_int_counter_vec!(
                "gateway_upstream_errors_total",
                "Failures reaching or reading from an upstream.",
                &["upstream"]
            )?,
            retries: register_int_counter_vec!(
                "gateway_retries_total",
                "Upstream attempts retried, by upstream.",
                &["upstream"]
            )?,
            spans_dropped: prometheus::register_int_counter!(
                "gateway_spans_dropped_total",
                "Spans discarded because the export queue was full. \
                 Non-zero means the collector cannot keep up; traffic is unaffected."
            )?,
            routes: register_int_gauge!("gateway_routes", "Routes in the active table.")?,
            cache: register_int_counter_vec!(
                "gateway_cache_total",
                "Cache outcomes per route: hit, miss, expired, bypass.",
                &["route", "outcome"]
            )?,
            circuit: register_int_gauge_vec!(
                "gateway_circuit_state",
                "Circuit breaker state per upstream: 0 closed, 1 half-open, 2 open.",
                &["upstream"]
            )?,
            backends: register_int_gauge_vec!(
                "gateway_pool_backends",
                "Backends in each pool, by health state.",
                &["upstream", "state"]
            )?,
        })
    }

    pub fn record_request(&self, route: &str, method: &str, status: u16, seconds: f64) {
        let route = route_label(route);
        self.requests
            .with_label_values(&[route, normalize_method(method), &status.to_string()])
            .inc();
        self.duration.with_label_values(&[route]).observe(seconds);
    }

    pub fn record_rejection(&self, event: &str, reason: &str) {
        self.rejections
            .with_label_values(&[event, &normalize_reason(reason)])
            .inc();
    }

    pub fn record_upstream_error(&self, upstream: &str) {
        self.upstream_errors
            .with_label_values(&[route_label(upstream)])
            .inc();
    }

    pub fn record_retry(&self, upstream: &str) {
        self.retries
            .with_label_values(&[route_label(upstream)])
            .inc();
    }

    pub fn record_cache(&self, route: &str, outcome: &str) {
        self.cache
            .with_label_values(&[route_label(route), outcome])
            .inc();
    }

    pub fn set_circuit_state(&self, upstream: &str, state: i64) {
        self.circuit
            .with_label_values(&[route_label(upstream)])
            .set(state);
    }

    pub fn record_span_dropped(&self) {
        self.spans_dropped.inc();
    }

    pub fn set_routes(&self, n: usize) {
        self.routes.set(i64::try_from(n).unwrap_or(i64::MAX));
    }

    pub fn set_pool_health(&self, upstream: &str, healthy: usize, unhealthy: usize) {
        self.backends
            .with_label_values(&[upstream, "healthy"])
            .set(i64::try_from(healthy).unwrap_or(i64::MAX));
        self.backends
            .with_label_values(&[upstream, "unhealthy"])
            .set(i64::try_from(unhealthy).unwrap_or(i64::MAX));
    }
}

/// Route ids come from configuration and are safe as labels; an empty one means
/// nothing matched.
fn route_label(route: &str) -> &str {
    if route.is_empty() { NO_ROUTE } else { route }
}

/// Collapse anything but a known HTTP method to `OTHER`.
///
/// A client chooses its own method, so without this a loop sending random
/// verbs would allocate a time series per verb, forever.
pub fn normalize_method(method: &str) -> &'static str {
    KNOWN_METHODS
        .iter()
        .find(|m| m.eq_ignore_ascii_case(method))
        .copied()
        .unwrap_or("OTHER")
}

/// Map reasons to a finite vocabulary. Truncating arbitrary input still
/// permits an unbounded number of distinct time series. Extension details
/// remain available in logs and share the `other` metric label.
pub fn normalize_reason(reason: &str) -> String {
    let slug = reason.split(':').next().unwrap_or(reason).trim();
    for prefix in [
        "unknown_issuer",
        "client_sent",
        "no_upstream",
        "missing_extension",
    ] {
        if slug == prefix
            || slug
                .strip_prefix(prefix)
                .is_some_and(|tail| tail.starts_with('_'))
        {
            return prefix.into();
        }
    }
    match slug {
        "" => NO_ROUTE,
        "deny_list"
        | "outside_base_path"
        | "unsafe_path"
        | "not_allowlisted"
        | "missing_bearer"
        | "invalid_token"
        | "no_verifier"
        | "no_machine_secret"
        | "bad_machine_credential"
        | "rate_limited"
        | "circuit_open"
        | "binding_refused"
        | "bind_without_identity"
        | "identity_mint_failed"
        | "upstream_timeout"
        | "body_too_large" => slug,
        _ => "other",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_methods_keep_their_name() {
        assert_eq!(normalize_method("GET"), "GET");
        assert_eq!(normalize_method("post"), "POST");
        assert_eq!(normalize_method("PATCH"), "PATCH");
    }

    #[test]
    fn an_invented_method_cannot_create_a_time_series() {
        // Otherwise a loop of random verbs grows the process without bound.
        assert_eq!(normalize_method("FOOBAR"), "OTHER");
        assert_eq!(normalize_method(""), "OTHER");
        assert_eq!(normalize_method(&"A".repeat(5000)), "OTHER");
    }

    #[test]
    fn a_reason_keeps_only_its_stable_slug() {
        assert_eq!(normalize_reason("deny_list"), "deny_list");
        assert_eq!(
            normalize_reason("identity_mint_failed: key rejected by backend"),
            "identity_mint_failed",
            "the detail after the colon is unbounded and must not be a label"
        );
    }

    #[test]
    fn request_derived_reasons_have_bounded_cardinality() {
        for i in 0..1000 {
            assert_eq!(
                normalize_reason(&format!("unknown_issuer_attacker-{i}")),
                "unknown_issuer"
            );
            assert_eq!(
                normalize_reason(&format!("extension rejected user {i}")),
                "other"
            );
        }
        assert_eq!(normalize_reason(&"x".repeat(500)), "other");
    }

    #[test]
    fn an_empty_label_is_rendered_as_a_placeholder() {
        assert_eq!(route_label(""), NO_ROUTE);
        assert_eq!(route_label("users-api"), "users-api");
        assert_eq!(normalize_reason(""), NO_ROUTE);
    }
}
