//! Retrying a failed upstream attempt.
//!
//! ```yaml
//! retry:
//!   attempts: 2
//!   on: [connection_failure, transport_error]
//! ```
//!
//! # Why this is conservative
//!
//! A retry is only safe when the upstream did not process the first attempt.
//! Get that wrong on a payment or an order and the retry is a duplicate
//! charge, so the decision turns on *where* the failure happened rather than
//! on how it looked:
//!
//! | failure | upstream saw the request? | retry |
//! |---|---|---|
//! | could not connect | no | any method |
//! | error on an established connection | possibly | idempotent methods only |
//!
//! [RFC 9110] defines GET, HEAD, OPTIONS, TRACE, PUT and DELETE as idempotent.
//! POST and PATCH are not, and are never retried after a connection was
//! established unless `non_idempotent: true` says the upstream can handle a
//! duplicate — which is a claim about the upstream, not about the gateway.
//!
//! [RFC 9110]: https://www.rfc-editor.org/rfc/rfc9110#name-idempotent-methods

use crate::config::{RetryConfig, RetryOn};

/// Methods RFC 9110 defines as idempotent: repeating one has the same effect
/// as making it once.
const IDEMPOTENT: &[&str] = &["GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE"];

pub fn is_idempotent(method: &str) -> bool {
    IDEMPOTENT.iter().any(|m| m.eq_ignore_ascii_case(method))
}

/// Where the attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// No connection was established, so the request was never delivered.
    Connect,
    /// The connection was up. The upstream may have received, and acted on,
    /// the request before it broke.
    Transport,
}

/// The retry rules for one route, resolved at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub attempts: u32,
    pub on_connect: bool,
    pub on_transport: bool,
    pub non_idempotent: bool,
}

impl Policy {
    pub fn from_config(cfg: &RetryConfig) -> Self {
        Self {
            attempts: cfg.attempts,
            on_connect: cfg.on.contains(&RetryOn::ConnectionFailure),
            on_transport: cfg.on.contains(&RetryOn::TransportError),
            non_idempotent: cfg.non_idempotent,
        }
    }

    /// Whether to make another attempt.
    ///
    /// `attempts_made` counts retries already performed, not the original
    /// request, so `attempts: 2` permits three deliveries in total.
    ///
    /// `body_replayable` is false once the request body has been streamed past
    /// the point it can be sent again — retrying then would deliver a request
    /// with a truncated body, which is worse than the failure it is trying to
    /// paper over.
    pub fn should_retry(
        &self,
        failure: Failure,
        attempts_made: u32,
        method: &str,
        body_replayable: bool,
    ) -> bool {
        if attempts_made >= self.attempts || !body_replayable {
            return false;
        }

        match failure {
            // Nothing was delivered, so repeating it cannot duplicate an
            // effect — the method does not matter.
            Failure::Connect => self.on_connect,
            // The upstream may already have acted on it.
            Failure::Transport => {
                self.on_transport && (self.non_idempotent || is_idempotent(method))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            attempts: 2,
            on_connect: true,
            on_transport: true,
            non_idempotent: false,
        }
    }

    #[test]
    fn a_connect_failure_is_retried_for_any_method() {
        // The request was never delivered, so there is nothing to duplicate.
        let p = policy();
        for m in ["GET", "POST", "PATCH", "DELETE"] {
            assert!(
                p.should_retry(Failure::Connect, 0, m, true),
                "{m} should retry on a connect failure"
            );
        }
    }

    #[test]
    fn a_transport_error_is_not_retried_for_a_post() {
        // This is the one that duplicates an order or a charge.
        let p = policy();
        assert!(!p.should_retry(Failure::Transport, 0, "POST", true));
        assert!(!p.should_retry(Failure::Transport, 0, "PATCH", true));
    }

    #[test]
    fn a_transport_error_is_retried_for_idempotent_methods() {
        let p = policy();
        for m in ["GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"] {
            assert!(
                p.should_retry(Failure::Transport, 0, m, true),
                "{m} is idempotent and should retry"
            );
        }
    }

    #[test]
    fn non_idempotent_retries_are_opt_in() {
        let mut p = policy();
        assert!(!p.should_retry(Failure::Transport, 0, "POST", true));
        p.non_idempotent = true;
        assert!(
            p.should_retry(Failure::Transport, 0, "POST", true),
            "an explicit opt-in is a claim that the upstream tolerates a duplicate"
        );
    }

    #[test]
    fn attempts_are_bounded() {
        let p = policy();
        assert!(p.should_retry(Failure::Connect, 0, "GET", true));
        assert!(p.should_retry(Failure::Connect, 1, "GET", true));
        assert!(
            !p.should_retry(Failure::Connect, 2, "GET", true),
            "attempts: 2 means two retries, not more"
        );
    }

    #[test]
    fn an_unreplayable_body_is_never_retried() {
        // Re-sending with a truncated body delivers a corrupt request, which is
        // worse than surfacing the original failure.
        let p = policy();
        assert!(!p.should_retry(Failure::Connect, 0, "GET", false));
        assert!(!p.should_retry(Failure::Transport, 0, "PUT", false));
    }

    #[test]
    fn each_failure_kind_can_be_disabled() {
        let p = Policy {
            on_transport: false,
            ..policy()
        };
        assert!(p.should_retry(Failure::Connect, 0, "GET", true));
        assert!(!p.should_retry(Failure::Transport, 0, "GET", true));
    }

    #[test]
    fn zero_attempts_never_retries() {
        let p = Policy {
            attempts: 0,
            ..policy()
        };
        assert!(!p.should_retry(Failure::Connect, 0, "GET", true));
    }

    #[test]
    fn idempotency_follows_rfc_9110() {
        for m in ["GET", "head", "OPTIONS", "TRACE", "put", "DELETE"] {
            assert!(is_idempotent(m), "{m} is idempotent");
        }
        for m in ["POST", "patch", "CONNECT", "WHATEVER"] {
            assert!(!is_idempotent(m), "{m} is not idempotent");
        }
    }
}
