//! Refusing connections before they become requests.
//!
//! Every other control in this gateway runs once a request exists. That leaves
//! a gap: opening a socket and saying nothing costs the sender almost nothing,
//! and until one of the downstream timeouts fires the connection is a file
//! descriptor, a task and a buffer that a real caller cannot have. Enough of
//! them and the listener stops accepting, which is an outage that never reached
//! a single line of routing code.
//!
//! Pingora's [`ConnectionFilter`] runs immediately after `accept()` and before
//! the TLS handshake, which is the only place this can be caught. The peer
//! address is all it gets, and the peer address is all that is needed.
//!
//! # Rate, not count
//!
//! The trait reports accepts and never reports closes, so a live count cannot
//! be kept honestly from here — it would drift upward until it refused
//! everyone. What is counted instead is **how fast one address may open new
//! connections**, which is the shape of the attack anyway.
//!
//! The absolute request-header deadline bounds sockets that never finish a
//! header. Long-lived responses can still outlive it, so this is not a hard
//! concurrent-connection ceiling; use an ingress limit for that.
//!
//! # This is a blunt instrument, and it is off by default
//!
//! Addresses are not callers. A corporate NAT, a mobile carrier gateway, or the
//! ingress controller in front of this gateway can legitimately be thousands of
//! people on one IP — and the ingress case is the normal deployment, where
//! *every* connection arrives from one address. Turning this on there would
//! throttle the whole gateway.
//!
//! So it stays off unless configured, and it is the right control only where
//! Lagos is genuinely the edge.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::ratelimit::Limiter;

/// Admits connections until one address opens them too quickly.
pub struct ConnectionLimiter {
    limiter: Arc<Limiter>,
}

impl std::fmt::Debug for ConnectionLimiter {
    /// `ConnectionFilter` requires `Debug`, and the interesting contents are
    /// per-address counters that have no business in a log line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionLimiter").finish_non_exhaustive()
    }
}

impl ConnectionLimiter {
    pub fn new(cfg: &crate::config::ConnectionLimitConfig) -> Self {
        Self {
            limiter: Arc::new(Limiter::new(&cfg.as_rate_limit())),
        }
    }

    /// Whether this address may open another connection now.
    ///
    /// Split from the trait method so it can be tested without a socket.
    pub fn admits(&self, ip: std::net::IpAddr) -> bool {
        // The socket peer, never a header: nothing has been parsed yet, and at
        // this point in the connection nothing could have been.
        self.limiter.check(&ip.to_string()).allowed
    }
}

#[async_trait::async_trait]
impl pingora::listeners::ConnectionFilter for ConnectionLimiter {
    async fn should_accept(&self, addr: Option<&SocketAddr>) -> bool {
        // No peer address means a Unix socket, which is not something an
        // attacker on the network can open. Admit it rather than inventing a
        // key that would lump every local connection into one bucket.
        let Some(addr) = addr else {
            return true;
        };

        if self.admits(addr.ip()) {
            return true;
        }

        // Dropped, not answered. There is no request to refuse yet and no
        // protocol in which to say why, and a flood is exactly the moment not
        // to spend a response on each attempt.
        if let Some(m) = crate::metrics::metrics() {
            m.record_rejection("gateway.connection.refused", "connection_rate");
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConnectionLimitConfig;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    fn limiter(rate: u64) -> ConnectionLimiter {
        ConnectionLimiter::new(&ConnectionLimitConfig {
            connections: rate,
            interval: Duration::from_secs(60),
            max_tracked: 1000,
        })
    }

    fn v4(a: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, a))
    }

    #[test]
    fn a_burst_from_one_address_is_cut_off() {
        let l = limiter(10);
        let admitted = (0..40).filter(|_| l.admits(v4(7))).count();
        assert_eq!(admitted, 10, "the quota, and not one connection more");
    }

    #[test]
    fn one_noisy_address_does_not_refuse_anyone_else() {
        // The failure that would matter most: a flood from a single source
        // taking the gateway away from everybody.
        let l = limiter(5);
        for _ in 0..50 {
            l.admits(v4(7));
        }
        assert!(
            l.admits(v4(8)),
            "a different address must still be admitted"
        );
        assert!(l.admits(v4(9)));
    }

    #[test]
    fn ipv6_addresses_are_counted_separately_from_each_other() {
        let l = limiter(1);
        let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
        assert!(l.admits(a));
        assert!(!l.admits(a));
        assert!(l.admits(b));
    }

    #[tokio::test]
    async fn a_unix_socket_peer_is_always_admitted() {
        use pingora::listeners::ConnectionFilter as _;
        // A quota of zero would refuse everything that is counted; a peerless
        // connection must not be counted at all.
        let l = limiter(1);
        assert!(l.should_accept(None).await);
        assert!(l.should_accept(None).await);
    }

    #[tokio::test]
    async fn the_socket_address_is_what_is_counted() {
        use pingora::listeners::ConnectionFilter as _;
        let l = limiter(2);
        let addr: SocketAddr = "203.0.113.7:51234".parse().expect("valid");
        // A different source port is the same client; the port must not be
        // part of the key or every connection would get its own quota.
        let other: SocketAddr = "203.0.113.7:51235".parse().expect("valid");
        assert!(l.should_accept(Some(&addr)).await);
        assert!(l.should_accept(Some(&other)).await);
        assert!(!l.should_accept(Some(&addr)).await);
    }
}
