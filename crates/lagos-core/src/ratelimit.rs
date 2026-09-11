//! Local rate limiting.
//!
//! Counters live in this process. That is a deliberate default, not a
//! shortcut: it needs no Redis, no clock sync and no network hop on the
//! request path. The cost is that a limit of 100/min across three gateway
//! instances admits up to 300/min, which for protecting an upstream from
//! runaway clients is usually the right trade. A shared backend can be added
//! behind the same [`Limiter`] interface when a deployment needs exactness.
//!
//! # Algorithm
//!
//! A sliding window counter: each key keeps the count for the current window
//! and the one before it, and the previous window is weighted by how much of
//! it is still in view. It costs two integers per key and, unlike a fixed
//! window, cannot be gamed by sending a full quota either side of a boundary.
//!
//! # Memory
//!
//! Keys come from requests, so the store must be bounded or it is a
//! memory-exhaustion bug. Entries are held in a capacity-limited cache with a
//! TTL of two windows; under key-space flooding the oldest are evicted, which
//! degrades limiting for those keys rather than the process.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::{Counter, RateLimitConfig, RateLimitKey};

/// One key's view of the current and previous window.
#[derive(Debug)]
struct Window {
    start: Instant,
    current: u64,
    previous: u64,
}

impl Window {
    fn new(now: Instant) -> Self {
        Self {
            start: now,
            current: 0,
            previous: 0,
        }
    }

    /// Roll the window forward to `now`, then decide.
    fn check(&mut self, now: Instant, limit: u64, interval: Duration) -> Decision {
        let interval_secs = interval.as_secs_f64().max(f64::MIN_POSITIVE);
        let mut elapsed = now.saturating_duration_since(self.start);

        if elapsed >= interval.saturating_mul(2) {
            // Idle for more than two windows: nothing from before is in view.
            *self = Window::new(now);
            elapsed = Duration::ZERO;
        } else if elapsed >= interval {
            self.previous = self.current;
            self.current = 0;
            self.start += interval;
            elapsed = elapsed.saturating_sub(interval);
        }

        // How far into the current window we are, 0.0..1.0.
        let progress = (elapsed.as_secs_f64() / interval_secs).clamp(0.0, 1.0);
        let estimated = (self.previous as f64) * (1.0 - progress) + (self.current as f64);

        if estimated >= limit as f64 {
            // Enough of the previous window has to age out for one slot to free
            // up; at minimum wait for the rest of this window.
            let remaining_window = interval_secs * (1.0 - progress);
            return Decision {
                allowed: false,
                limit,
                remaining: 0,
                retry_after: Duration::from_secs_f64(remaining_window.max(1.0).ceil()),
            };
        }

        self.current = self.current.saturating_add(1);

        // `estimated < limit` on this branch, and the result is clamped at 0,
        // so the value is in `[0, limit)` — within `u64` and non-negative by
        // construction. The cast cannot truncate or lose a sign.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let remaining = (limit as f64 - estimated - 1.0).max(0.0) as u64;

        Decision {
            allowed: true,
            limit,
            remaining,
            retry_after: Duration::ZERO,
        }
    }
}

/// What the limiter decided, and what to tell the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub limit: u64,
    pub remaining: u64,
    pub retry_after: Duration,
}

/// Where the counts live.
enum Counters {
    /// One window per key, exact.
    Exact(moka::sync::Cache<String, Arc<Mutex<Window>>>),
    /// A shared count-min sketch. Fixed memory, lock-free, over-counts on
    /// collision.
    Sketch(pingora_limits::rate::Rate),
}

/// A rate limiter over one of two counting backends.
pub struct Limiter {
    counters: Counters,
    limit: u64,
    interval: Duration,
}

impl std::fmt::Debug for Limiter {
    /// Deliberately opaque: the interesting contents are per-caller counters,
    /// and a route's `Debug` output ends up in logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Limiter")
            .field("limit", &self.limit)
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

impl Limiter {
    pub fn new(cfg: &RateLimitConfig) -> Self {
        let counters = match cfg.counter {
            Counter::Exact => Counters::Exact(
                moka::sync::Cache::builder()
                    .max_capacity(cfg.max_keys)
                    // Two windows is exactly how far back the algorithm can
                    // see; anything older contributes nothing and need not be
                    // kept.
                    .time_to_idle(cfg.interval.saturating_mul(2))
                    .build(),
            ),
            Counter::Sketch => Counters::Sketch(pingora_limits::rate::Rate::new(cfg.interval)),
        };
        Self {
            counters,
            limit: cfg.requests,
            interval: cfg.interval,
        }
    }

    /// Count one request against `key`.
    pub fn check(&self, key: &str) -> Decision {
        self.check_at(key, Instant::now())
    }

    fn check_at(&self, key: &str, now: Instant) -> Decision {
        match &self.counters {
            Counters::Exact(windows) => self.check_exact(windows, key, now),
            Counters::Sketch(rate) => self.check_sketch(rate, key),
        }
    }

    /// The sketch path.
    ///
    /// `pingora-limits` supplies the same sliding-window estimate this crate
    /// computes by hand — `prev * (1 - fraction) + curr` — so a limit means the
    /// same thing on either backend.
    ///
    /// It is read-then-write rather than one atomic step, so two concurrent
    /// requests at the boundary can both be admitted. That is inherent to a
    /// lock-free counter and the overshoot is one request per racing pair;
    /// refusing to count at all would be worse.
    fn check_sketch(&self, rate: &pingora_limits::rate::Rate, key: &str) -> Decision {
        let weighted = rate.rate_with(&key, |c| {
            (c.prev_samples as f64) * (1.0 - c.current_interval_fraction) + (c.curr_samples as f64)
        });

        if weighted >= self.limit as f64 {
            return Decision {
                allowed: false,
                limit: self.limit,
                remaining: 0,
                // The sketch does not expose how far into the window it is, so
                // the whole interval is the honest answer.
                retry_after: Duration::from_secs(self.interval.as_secs().max(1)),
            };
        }

        // Only successful requests are counted, matching the exact backend: a
        // refused request must not extend its own block.
        rate.observe(&key, 1);

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let remaining = (self.limit as f64 - weighted - 1.0).max(0.0) as u64;
        Decision {
            allowed: true,
            limit: self.limit,
            remaining,
            retry_after: Duration::ZERO,
        }
    }

    fn check_exact(
        &self,
        windows: &moka::sync::Cache<String, Arc<Mutex<Window>>>,
        key: &str,
        now: Instant,
    ) -> Decision {
        let entry = windows.get_with_by_ref(key, || Arc::new(Mutex::new(Window::new(now))));

        // The critical section is a few integer operations with no await and
        // no call into unknown code, so it cannot deadlock. A poisoned lock
        // would mean a panic inside it, which the code above cannot produce —
        // recovering keeps limiting working rather than failing every request
        // that shares the key.
        let mut window = match entry.lock() {
            Ok(w) => w,
            Err(poisoned) => poisoned.into_inner(),
        };
        window.check(now, self.limit, self.interval)
    }

    /// Keys currently tracked, or `None` for the sketch, which holds a fixed
    /// number of counters regardless of how many keys it has seen.
    pub fn tracked(&self) -> Option<u64> {
        match &self.counters {
            Counters::Exact(windows) => {
                windows.run_pending_tasks();
                Some(windows.entry_count())
            }
            Counters::Sketch(_) => None,
        }
    }
}

/// The client address to limit on, resolved against the number of proxies in
/// front of the gateway.
///
/// `X-Forwarded-For` is appended to by each hop, so entries are ordered
/// oldest-first and **only the rightmost ones are trustworthy** — anything
/// further left was supplied by the client. Counting from the right is what
/// makes this safe: with `trusted_proxies: 0` nothing in the header is
/// believed and the socket peer is used; with `1` the last entry is taken,
/// which the single proxy in front appended itself.
///
/// Getting this wrong is a bypass, not a detail: trusting the *first* entry
/// would let a client mint a fresh quota per forged address.
pub fn client_address(
    forwarded_for: Option<&str>,
    peer: Option<&str>,
    trusted_proxies: usize,
) -> Option<String> {
    if trusted_proxies == 0 {
        return peer.map(str::to_string);
    }

    let mut chain: Vec<&str> = forwarded_for
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if let Some(p) = peer {
        chain.push(p);
    }

    // `trusted_proxies` hops back from the right-hand end.
    chain
        .len()
        .checked_sub(trusted_proxies)
        .and_then(|i| i.checked_sub(1))
        .and_then(|i| chain.get(i))
        .map(|s| (*s).to_string())
        // A chain shorter than the configured depth means the request did not
        // arrive through the expected proxies. Fall back to the socket peer
        // rather than to a client-supplied entry.
        .or_else(|| peer.map(str::to_string))
}

/// Build the limiter key for a request.
///
/// Returns `None` when the configured key cannot be determined, which the
/// caller treats as "not limited" — a limit keyed on something absent would
/// otherwise lump every such caller into one bucket and throttle them
/// collectively.
pub fn key_for(
    cfg: &RateLimitConfig,
    route_id: &str,
    subject: Option<&str>,
    forwarded_for: Option<&str>,
    peer: Option<&str>,
    header: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    let raw = match &cfg.key {
        RateLimitKey::Ip => client_address(forwarded_for, peer, cfg.trusted_proxies)?,
        RateLimitKey::Identity => subject?.to_string(),
        RateLimitKey::Route => String::new(),
        RateLimitKey::Header(name) => header(name)?,
    };
    // Scoped per route so two routes sharing a limit definition do not share a
    // budget; a caller's quota on `/search` is not spent by `/orders`.
    Some(format!("{route_id}|{raw}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(requests: u64, interval: Duration) -> RateLimitConfig {
        RateLimitConfig {
            requests,
            interval,
            key: RateLimitKey::Ip,
            trusted_proxies: 0,
            max_keys: 1000,
            counter: Counter::Exact,
        }
    }

    fn sketch_cfg(requests: u64, interval: Duration) -> RateLimitConfig {
        RateLimitConfig {
            counter: Counter::Sketch,
            ..cfg(requests, interval)
        }
    }

    #[test]
    fn allows_up_to_the_limit_then_refuses() {
        let l = Limiter::new(&cfg(3, Duration::from_secs(60)));
        for i in 0..3 {
            let d = l.check("k");
            assert!(d.allowed, "request {i} should be allowed");
        }
        let d = l.check("k");
        assert!(!d.allowed);
        assert_eq!(d.remaining, 0);
        assert!(
            d.retry_after > Duration::ZERO,
            "a 429 must say when to retry"
        );
    }

    #[test]
    fn remaining_counts_down() {
        let l = Limiter::new(&cfg(3, Duration::from_secs(60)));
        assert_eq!(l.check("k").remaining, 2);
        assert_eq!(l.check("k").remaining, 1);
        assert_eq!(l.check("k").remaining, 0);
    }

    #[test]
    fn keys_are_independent() {
        let l = Limiter::new(&cfg(1, Duration::from_secs(60)));
        assert!(l.check("a").allowed);
        assert!(!l.check("a").allowed);
        assert!(
            l.check("b").allowed,
            "one key must not spend another's quota"
        );
    }

    #[test]
    fn the_window_recovers_once_it_has_passed() {
        let interval = Duration::from_secs(60);
        let l = Limiter::new(&cfg(2, interval));
        let t0 = Instant::now();
        assert!(l.check_at("k", t0).allowed);
        assert!(l.check_at("k", t0).allowed);
        assert!(!l.check_at("k", t0).allowed);

        // Two full windows later nothing earlier is in view.
        let t2 = t0 + interval * 2;
        assert!(l.check_at("k", t2).allowed, "quota should have recovered");
    }

    #[test]
    fn a_boundary_burst_cannot_double_the_quota() {
        // The failure a fixed window has: spend a full quota at the end of one
        // window and another at the start of the next, and an upstream sees 2x
        // the limit within a moment. The previous window is weighted in, so the
        // quota is released gradually instead.
        let interval = Duration::from_secs(60);
        let l = Limiter::new(&cfg(10, interval));
        let t0 = Instant::now();
        for _ in 0..10 {
            assert!(l.check_at("k", t0).allowed);
        }

        let just_after = t0 + interval + Duration::from_secs(1);
        let granted = (0..10)
            .filter(|_| l.check_at("k", just_after).allowed)
            .count();
        assert!(
            granted <= 1,
            "a fixed window would grant 10 more here; got {granted}"
        );
    }

    #[test]
    fn the_quota_is_released_gradually_across_the_window() {
        let interval = Duration::from_secs(60);
        let l = Limiter::new(&cfg(10, interval));
        let t0 = Instant::now();
        for _ in 0..10 {
            assert!(l.check_at("k", t0).allowed);
        }

        // Halfway through the next window half the old count has aged out.
        let half = t0 + interval + interval / 2;
        let granted = (0..10).filter(|_| l.check_at("k", half).allowed).count();
        assert!(
            (4..=6).contains(&granted),
            "about half the quota should be available, got {granted}"
        );
    }

    #[test]
    fn the_store_is_bounded() {
        let mut c = cfg(10, Duration::from_secs(60));
        c.max_keys = 10;
        let l = Limiter::new(&c);
        for i in 0..500 {
            l.check(&format!("key-{i}"));
        }
        assert!(
            l.tracked().is_some_and(|n| n <= 20),
            "a flood of keys must not grow without bound, got {:?}",
            l.tracked()
        );
    }

    // --- the sketch backend ---------------------------------------------

    #[test]
    fn the_sketch_backend_enforces_the_same_limit() {
        let l = Limiter::new(&sketch_cfg(3, Duration::from_secs(60)));
        for i in 0..3 {
            assert!(l.check("k").allowed, "request {i} should be allowed");
        }
        let d = l.check("k");
        assert!(!d.allowed);
        assert!(d.retry_after > Duration::ZERO);
    }

    #[test]
    fn the_sketch_backend_holds_a_fixed_amount_of_memory() {
        // The reason to choose it: a million distinct keys cost the same as one.
        let l = Limiter::new(&sketch_cfg(10, Duration::from_secs(60)));
        for i in 0..100_000 {
            l.check(&format!("key-{i}"));
        }
        assert_eq!(
            l.tracked(),
            None,
            "the sketch holds a fixed set of counters, not per-key state"
        );
    }

    #[test]
    fn the_sketch_backend_keeps_distinct_keys_mostly_separate() {
        // Collisions exist by design, but they must be the exception — if every
        // key shared a counter the limiter would be useless.
        let l = Limiter::new(&sketch_cfg(1, Duration::from_secs(60)));
        let refused = (0..200)
            .filter(|i| !l.check(&format!("caller-{i}")).allowed)
            .count();
        assert!(
            refused < 20,
            "{refused} of 200 distinct keys collided; the sketch is too small"
        );
    }

    #[test]
    fn the_exact_backend_never_refuses_an_innocent_key() {
        // The contrast, and the reason `exact` is the default: no collisions at
        // all, so a 429 is always the caller's own doing.
        let l = Limiter::new(&cfg(1, Duration::from_secs(60)));
        let refused = (0..200)
            .filter(|i| !l.check(&format!("caller-{i}")).allowed)
            .count();
        assert_eq!(refused, 0);
    }

    // --- client address ------------------------------------------------

    #[test]
    fn with_no_trusted_proxy_only_the_socket_peer_is_believed() {
        // The client sent a forged chain; it must be ignored entirely.
        assert_eq!(
            client_address(Some("1.2.3.4, 5.6.7.8"), Some("10.0.0.1"), 0).as_deref(),
            Some("10.0.0.1")
        );
    }

    #[test]
    fn with_one_trusted_proxy_the_last_entry_is_the_client() {
        // nginx appends the real client address to whatever the client sent.
        assert_eq!(
            client_address(Some("9.9.9.9, 203.0.113.7"), Some("10.0.0.1"), 1).as_deref(),
            Some("203.0.113.7")
        );
    }

    #[test]
    fn a_forged_prefix_cannot_mint_new_buckets() {
        // The attack: vary the left of the chain to get a fresh quota each time.
        let a = client_address(Some("1.1.1.1, 203.0.113.7"), Some("10.0.0.1"), 1);
        let b = client_address(Some("2.2.2.2, 203.0.113.7"), Some("10.0.0.1"), 1);
        let c = client_address(Some("3.3.3.3, 9.9.9.9, 203.0.113.7"), Some("10.0.0.1"), 1);
        assert_eq!(a, b);
        assert_eq!(b, c, "only the trusted hop may determine the key");
    }

    #[test]
    fn two_trusted_proxies_look_one_further_left() {
        assert_eq!(
            client_address(Some("203.0.113.7, 172.16.0.1"), Some("10.0.0.1"), 2).as_deref(),
            Some("203.0.113.7")
        );
    }

    #[test]
    fn a_chain_shorter_than_expected_falls_back_to_the_peer() {
        // Never to a client-supplied entry.
        assert_eq!(
            client_address(None, Some("10.0.0.1"), 2).as_deref(),
            Some("10.0.0.1")
        );
        assert_eq!(
            client_address(Some(""), Some("10.0.0.1"), 1).as_deref(),
            Some("10.0.0.1")
        );
    }

    #[test]
    fn keys_are_scoped_per_route() {
        let c = cfg(10, Duration::from_secs(60));
        let a = key_for(&c, "orders", None, None, Some("10.0.0.1"), |_| None);
        let b = key_for(&c, "search", None, None, Some("10.0.0.1"), |_| None);
        assert_ne!(a, b, "a quota spent on one route must not affect another");
    }

    #[test]
    fn an_undeterminable_key_is_not_limited() {
        // Lumping every anonymous caller into one bucket would throttle them
        // collectively, which is worse than not limiting them.
        let mut c = cfg(10, Duration::from_secs(60));
        c.key = RateLimitKey::Identity;
        assert!(key_for(&c, "r", None, None, Some("10.0.0.1"), |_| None).is_none());
        assert!(key_for(&c, "r", Some("user-1"), None, None, |_| None).is_some());
    }
}
