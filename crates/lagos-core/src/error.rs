//! Client-facing rejections.
//!
//! Bodies intentionally mirror the NestJS error envelope (`statusCode` /
//! `message` / `error`) so existing clients see no change during a migration.

use serde_json::json;

/// A terminal decision to answer the client directly instead of proxying.
#[derive(Debug, Clone)]
pub struct Rejection {
    pub status: u16,
    pub body: serde_json::Value,
    /// Structured log event name, e.g. `gateway.route.denied`.
    pub event: &'static str,
    /// Machine-readable reason recorded alongside the event.
    pub reason: String,
}

impl Rejection {
    pub fn new(
        status: u16,
        body: serde_json::Value,
        event: &'static str,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            status,
            body,
            event,
            reason: reason.into(),
        }
    }

    /// Everything the gateway refuses to route is a 404, never a 403 — a
    /// distinguishable response would let a caller enumerate the deny-list and
    /// learn which internal services exist.
    pub fn not_found(event: &'static str, reason: impl Into<String>) -> Self {
        Self::new(
            404,
            json!({ "statusCode": 404, "message": "Not Found", "error": "Not Found" }),
            event,
            reason,
        )
    }

    /// Too many requests.
    ///
    /// Carries `retry_after` so the caller is told when to come back rather
    /// than being left to guess and hammer the gateway.
    pub fn rate_limited(retry_after_secs: u64) -> Self {
        Self::new(
            429,
            json!({
                "statusCode": 429,
                "message": "Too many requests",
                "error": "Too Many Requests",
                "retryAfter": retry_after_secs,
            }),
            "gateway.rate_limited",
            "rate_limited",
        )
    }

    /// The circuit for this upstream is open.
    ///
    /// 503 with `Retry-After`: the service is expected back, and telling the
    /// caller roughly when stops it retrying immediately into a circuit that
    /// is still shedding load.
    pub fn circuit_open(retry_after_secs: u64) -> Self {
        Self::new(
            503,
            json!({
                "statusCode": 503,
                "message": "The upstream service is temporarily unavailable.",
                "error": "Service Unavailable",
                "retryAfter": retry_after_secs,
            }),
            "gateway.circuit_open",
            "circuit_open",
        )
    }

    pub fn missing_bearer() -> Self {
        Self::new(
            401,
            json!({
                "statusCode": 401,
                "message": "Authentication required. Please provide a valid bearer token in the Authorization header.",
                "error": "Unauthorized",
                "hint": "Use: Authorization: Bearer <id_token>",
            }),
            "gateway.auth.rejected",
            "missing_bearer",
        )
    }

    pub fn invalid_token(detail: impl Into<String>) -> Self {
        Self::new(
            401,
            json!({
                "statusCode": 401,
                "message": "Invalid token",
                "error": "Unauthorized",
                "hint": "Use a fresh ID token from getIdToken().",
            }),
            "gateway.auth.rejected",
            format!("invalid_token: {}", detail.into()),
        )
    }

    pub fn forbidden(message: &str, reason: impl Into<String>) -> Self {
        Self::new(
            403,
            json!({ "statusCode": 403, "message": message, "error": "Forbidden" }),
            "gateway.request.forbidden",
            reason,
        )
    }

    pub fn unavailable(message: &str, reason: impl Into<String>) -> Self {
        Self::new(
            503,
            json!({ "statusCode": 503, "message": message, "error": "Service Unavailable" }),
            "gateway.upstream.unavailable",
            reason,
        )
    }

    pub fn gateway_timeout() -> Self {
        Self::new(
            504,
            json!({ "statusCode": 504, "message": "Gateway Timeout", "error": "Gateway Timeout" }),
            "gateway.upstream.timeout",
            "upstream_timeout",
        )
    }

    pub fn payload_too_large() -> Self {
        Self::new(
            413,
            json!({ "statusCode": 413, "message": "Payload Too Large", "error": "Payload Too Large" }),
            "gateway.request.too_large",
            "body_too_large",
        )
    }

    pub fn body_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.body).unwrap_or_else(|_| b"{}".to_vec())
    }
}
