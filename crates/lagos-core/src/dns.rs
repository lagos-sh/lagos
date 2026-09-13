//! Upstream name resolution, off the request path.
//!
//! A single-target upstream keeps its hostname rather than an address, so that
//! a record change — a Service re-pointed, a pod replaced — is picked up
//! without restarting the gateway. That is the right behaviour, but it means
//! *something* has to resolve a name on the way to choosing a peer.
//!
//! Doing it with [`std::net::ToSocketAddrs`], as the proxy did before this
//! module, calls `getaddrinfo` — a **blocking** syscall — directly on a Pingora
//! worker thread, once per request. With the default two worker threads, a
//! resolver having a bad minute does not slow the gateway down, it stops it:
//! both workers sit in libc while every other connection waits. That turns a
//! DNS wobble into a gateway outage, and it makes slow DNS an amplifier for
//! anyone sending traffic.
//!
//! Two things fix it, and both are needed:
//!
//! 1. **Resolve asynchronously.** [`tokio::net::lookup_host`] runs the same
//!    blocking call on the runtime's blocking pool, where blocking is what the
//!    threads are for.
//! 2. **Cache the answer.** Even a fast lookup is a syscall and usually a round
//!    trip to a resolver, per request, forever. A short TTL keeps the
//!    pick-up-changes-without-a-restart property while making the common case
//!    free.
//!
//! An address that is already an IP literal skips both: there is nothing to
//! resolve and nothing worth remembering.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Resolved names, held for as long as the configured TTL.
pub struct Resolver {
    /// `None` when caching is disabled, in which case every call resolves —
    /// still asynchronously, which is the half that was actually a bug.
    cache: Option<moka::future::Cache<String, Arc<Vec<SocketAddr>>>>,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver")
            .field("caching", &self.cache.is_some())
            .finish()
    }
}

impl Resolver {
    /// Build a resolver. A zero TTL disables caching.
    ///
    /// `max_entries` bounds the store. Upstream names come from configuration,
    /// not from requests, so this cannot be flooded by a caller — the cap is
    /// there because an unbounded map in a long-lived process is a bad habit
    /// regardless of who fills it.
    pub fn new(ttl: Duration, max_entries: u64) -> Self {
        let cache = (!ttl.is_zero()).then(|| {
            moka::future::Cache::builder()
                .max_capacity(max_entries)
                // Time to *live*, not idle: a name that is constantly in use
                // must still be re-resolved, or a record change would never be
                // seen on exactly the upstreams that matter most.
                .time_to_live(ttl)
                .build()
        });
        Self { cache }
    }

    /// Resolve `addr` (`host:port`) to a socket address.
    ///
    /// # Errors
    ///
    /// A name that does not resolve, or resolves to nothing, is a connect
    /// error — the same failure a refused connection would be, so it becomes a
    /// 502 for the one request rather than anything worse. The message names
    /// only the configured upstream, which is operator input, and reaches logs
    /// rather than the response body.
    pub async fn resolve(&self, addr: &str) -> pingora::Result<SocketAddr> {
        // An IP literal needs no resolver and no cache entry.
        if let Ok(sock) = addr.parse::<SocketAddr>() {
            return Ok(sock);
        }

        let Some(cache) = &self.cache else {
            return first(addr, lookup(addr).await?);
        };

        // `try_get_with` coalesces concurrent misses for the same key into one
        // lookup, and does not cache the error. Without the coalescing, a
        // cold cache under load sends one resolver query per in-flight
        // request; without the second property, one DNS blip would be
        // remembered for the whole TTL.
        let addrs = cache
            .try_get_with(addr.to_string(), async { lookup(addr).await })
            .await
            .map_err(|e: Arc<Box<pingora::Error>>| {
                pingora::Error::explain(
                    pingora::ErrorType::ConnectError,
                    format!("upstream address {addr} did not resolve: {e}"),
                )
                .into_up()
            })?;

        first(addr, addrs)
    }
}

async fn lookup(addr: &str) -> pingora::Result<Arc<Vec<SocketAddr>>> {
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host(addr)
        .await
        .map_err(|e| {
            pingora::Error::explain(
                pingora::ErrorType::ConnectError,
                format!("upstream address {addr} did not resolve: {e}"),
            )
            .into_up()
        })?
        .collect();
    Ok(Arc::new(resolved))
}

/// The first address, matching what the blocking path returned.
fn first(addr: &str, addrs: Arc<Vec<SocketAddr>>) -> pingora::Result<SocketAddr> {
    addrs.first().copied().ok_or_else(|| {
        pingora::Error::explain(
            pingora::ErrorType::ConnectError,
            format!("upstream address {addr} resolved to no addresses"),
        )
        .into_up()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver() -> Resolver {
        Resolver::new(Duration::from_secs(30), 128)
    }

    #[tokio::test]
    async fn an_ip_literal_resolves_without_touching_dns() {
        // The fast path matters: an upstream written as an address should not
        // consult a resolver, a cache, or the blocking pool.
        let r = Resolver::new(Duration::ZERO, 0);
        let addr = r
            .resolve("127.0.0.1:3002")
            .await
            .expect("a literal must resolve");
        assert_eq!(addr.port(), 3002);
        assert!(addr.ip().is_loopback());
    }

    #[tokio::test]
    async fn an_ipv6_literal_is_not_split_on_its_colons() {
        let addr = resolver()
            .resolve("[::1]:8080")
            .await
            .expect("an IPv6 literal must resolve");
        assert_eq!(addr.port(), 8080);
        assert!(addr.ip().is_loopback());
    }

    #[tokio::test]
    async fn localhost_resolves_and_is_then_served_from_cache() {
        let r = resolver();
        let a = r
            .resolve("localhost:3002")
            .await
            .expect("localhost resolves");
        let b = r.resolve("localhost:3002").await.expect("cached");
        assert_eq!(a, b);
        assert_eq!(a.port(), 3002);
    }

    #[tokio::test]
    async fn an_unresolvable_name_is_an_error_not_a_panic() {
        // Before the proxy resolved names itself, pingora's `HttpPeer::new`
        // unwrapped this and took the worker down with it.
        let err = resolver()
            .resolve("no-such-host.invalid:3002")
            .await
            .expect_err("a name that cannot resolve must not yield a peer");
        assert_eq!(err.etype(), &pingora::ErrorType::ConnectError);
    }

    #[tokio::test]
    async fn a_failed_lookup_is_not_remembered() {
        // Caching a failure would turn one DNS blip into a TTL-long outage for
        // that upstream, long after the resolver recovered.
        let r = resolver();
        assert!(r.resolve("no-such-host.invalid:3002").await.is_err());
        assert!(r.resolve("localhost:3002").await.is_ok());
        // Still erroring, i.e. re-queried rather than served from a cached error.
        assert!(r.resolve("no-such-host.invalid:3002").await.is_err());
    }

    #[tokio::test]
    async fn a_malformed_address_is_an_error() {
        // No port: nothing can be dialled even if the name exists.
        assert!(resolver().resolve("products-service").await.is_err());
        assert!(resolver().resolve("").await.is_err());
    }
}
