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

    /// Never include the supplied key or credential in a rejection.
    pub fn limit_key(error: crate::ratelimit::KeyError) -> Self {
        Self::new(
            400,
            json!({"statusCode": 400, "message": "A valid policy key is required", "error": "Bad Request"}),
            "gateway.limit_key.rejected",
            match error {
                crate::ratelimit::KeyError::Missing => "missing_limit_key",
                crate::ratelimit::KeyError::Invalid => "invalid_limit_key",
            },
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

    /// Too many requests to this route are already in flight.
    ///
    /// A route-wide cap is the gateway shedding load, so it is a 503. A cap
    /// per caller is the caller's own doing, so it is a 429, the same answer
    /// as a rate limit. Slots free as soon as a response finishes, so the
    /// retry hint is short.
    pub fn concurrency_limited(per_caller: bool, retry_after_secs: u64) -> Self {
        let (status, message, error) = if per_caller {
            (429, "Too many concurrent requests", "Too Many Requests")
        } else {
            (
                503,
                "The upstream service is at capacity.",
                "Service Unavailable",
            )
        };
        Self::new(
            status,
            json!({
                "statusCode": status,
                "message": message,
                "error": error,
                "retryAfter": retry_after_secs,
            }),
            "gateway.concurrency_limited",
            "concurrency_limited",
        )
    }

    pub fn missing_bearer() -> Self {
        Self::new(
            401,
            json!({
                "statusCode": 401,
                "message": "Authentication required. Please provide a valid bearer token in the Authorization header.",
                "error": "Unauthorized",
                "hint": "Use: Authorization: Bearer <token>",
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
                // Provider-neutral: any configured issuer can reach this, and a
                // client told to call Firebase's getIdToken() when it signs in
                // somewhere else is sent looking for a function it does not have.
                "hint": "Refresh the token or sign in again, then retry.",
            }),
            "gateway.auth.rejected",
            format!("invalid_token: {}", detail.into()),
        )
    }

    /// No client key on a route that needs one. Names the header, since the
    /// caller is usually one of our own clients missing a configuration value.
    pub fn missing_client_key(header: &str) -> Self {
        Self::new(
            401,
            json!({
                "statusCode": 401,
                "message": "Client key required",
                "error": "Unauthorized",
                "hint": format!("Send the key in the {header} header."),
            }),
            "gateway.client_key.rejected",
            "missing_client_key",
        )
    }

    /// A client key that matches none of the configured keys. Deliberately
    /// says nothing about which part was wrong.
    pub fn invalid_client_key() -> Self {
        Self::new(
            401,
            json!({
                "statusCode": 401,
                "message": "Invalid client key",
                "error": "Unauthorized",
            }),
            "gateway.client_key.rejected",
            "bad_client_key",
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

#[cfg(test)]
mod tests {
    use super::Rejection;

    #[test]
    fn a_route_at_capacity_is_a_503_and_a_caller_at_theirs_a_429() {
        let route = Rejection::concurrency_limited(false, 1);
        let caller = Rejection::concurrency_limited(true, 1);
        assert_eq!(route.status, 503);
        assert_eq!(caller.status, 429);
        for rej in [route, caller] {
            assert_eq!(rej.body["statusCode"], rej.status);
            assert_eq!(rej.reason, "concurrency_limited");
        }
    }

    /// Lagos verifies tokens from any configured issuer, so what it tells a
    /// client must not assume one identity provider.
    #[test]
    fn auth_hints_name_no_identity_provider() {
        for rej in [
            Rejection::missing_bearer(),
            Rejection::invalid_token("expired"),
        ] {
            let body = String::from_utf8(rej.body_bytes()).unwrap_or_default();
            for provider_word in ["getIdToken", "id_token", "ID token", "Firebase"] {
                assert!(!body.contains(provider_word), "`{provider_word}` in {body}");
            }
        }
    }
}
