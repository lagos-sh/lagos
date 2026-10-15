//! Requests in flight, for `concurrency` caps.
//!
//! Two stores, because the two kinds of key want different things:
//!
//! - A **route-wide** cap has one key per route, so it is counted exactly: an
//!   atomic per route. A sketch would let one route's traffic, or any caller's,
//!   collide with it and refuse the whole route.
//! - A **per-caller** cap has a key per caller, from requests, so it needs
//!   memory that does not grow with them. That is `pingora-limits`' in-flight
//!   count-min sketch: fixed size, never under-counts, and over-counts only when
//!   a key collides with other in-flight keys in every row. With `N` distinct
//!   keys in flight at once the chance a given key is over-counted is about
//!   `(1 - e^(-N/8192))^4`: 0.02% at 1,000, 0.2% at 2,000, 2% at 4,000.
//!
//! One store per gateway rather than per route table, so a route reload does
//! not reset the count while the requests it was counting are still running.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

pub struct InFlight {
    /// Keyed by the route's cap key. Grows only with configured route ids.
    routes: RwLock<HashMap<String, Arc<AtomicU64>>>,
    callers: pingora_limits::inflight::Inflight,
}

/// A held slot. Released when dropped.
pub enum Slot {
    Route(RouteSlot),
    Caller(pingora_limits::inflight::Guard),
}

pub struct RouteSlot(Arc<AtomicU64>);

impl Drop for RouteSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Default for InFlight {
    fn default() -> Self {
        Self::new()
    }
}

impl InFlight {
    pub fn new() -> Self {
        Self {
            routes: RwLock::default(),
            callers: pingora_limits::inflight::Inflight::new(),
        }
    }

    /// Take a slot under `max`, or `None` when the key is already at its cap.
    pub fn take(&self, key: &str, max: u64, per_caller: bool) -> Option<Slot> {
        if per_caller {
            // Incremented before it is compared, so a refused request counts
            // for an instant and is released as its guard drops.
            let (guard, count) = self.callers.incr(key, 1);
            return (u64::try_from(count).unwrap_or(0) <= max).then_some(Slot::Caller(guard));
        }
        let counter = self.route_counter(key);
        // Compare-and-swap rather than add-then-check: a refused request never
        // touches the count, so a burst at the cap cannot refuse requests that
        // would have fitted.
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < max).then(|| n.saturating_add(1))
            })
            .ok()
            .map(|_| Slot::Route(RouteSlot(counter)))
    }

    fn route_counter(&self, key: &str) -> Arc<AtomicU64> {
        // A poisoned lock means a panic while holding it, which neither
        // critical section below can produce; recover rather than refuse.
        if let Some(c) = self
            .routes
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(key)
        {
            return c.clone();
        }
        self.routes
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .entry(key.to_string())
            .or_default()
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_route_slot_is_held_until_it_drops() {
        let f = InFlight::new();
        let first = f.take("r|", 2, false).expect("first slot");
        let second = f.take("r|", 2, false).expect("second slot");
        assert!(f.take("r|", 2, false).is_none(), "over the cap");
        assert!(f.take("r|", 2, false).is_none(), "a refusal keeps no count");
        assert!(f.take("other|", 2, false).is_some(), "routes are separate");
        drop(first);
        let third = f.take("r|", 2, false).expect("a slot freed");
        drop((second, third));
        assert!(f.take("r|", 2, false).is_some());
    }

    #[test]
    fn a_route_cap_is_exact_whatever_callers_are_in_flight() {
        // Thousands of per-caller keys in flight must not push a route-wide
        // count over, which a shared sketch would.
        let f = InFlight::new();
        let callers: Vec<_> = (0..20_000)
            .filter_map(|i| f.take(&format!("r|caller-{i}"), 1_000, true))
            .collect();
        assert_eq!(callers.len(), 20_000);
        let held: Vec<_> = (0..3).filter_map(|_| f.take("r|", 3, false)).collect();
        assert_eq!(held.len(), 3, "exactly the cap, no collisions");
    }

    #[test]
    fn a_caller_slot_is_held_until_it_drops() {
        let f = InFlight::new();
        let first = f.take("r|a", 1, true).expect("first slot");
        assert!(f.take("r|a", 1, true).is_none(), "over the cap");
        assert!(f.take("r|b", 1, true).is_some(), "callers are separate");
        drop(first);
        assert!(f.take("r|a", 1, true).is_some(), "a refusal keeps no count");
    }

    #[test]
    fn concurrent_takers_never_exceed_a_route_cap() {
        let f = Arc::new(InFlight::new());
        let peak = Arc::new(AtomicU64::new(0));
        let live = Arc::new(AtomicU64::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (f, peak, live) = (f.clone(), peak.clone(), live.clone());
                std::thread::spawn(move || {
                    for _ in 0..2_000 {
                        if let Some(slot) = f.take("r|", 4, false) {
                            let n = live.fetch_add(1, Ordering::AcqRel) + 1;
                            peak.fetch_max(n, Ordering::AcqRel);
                            live.fetch_sub(1, Ordering::AcqRel);
                            drop(slot);
                        }
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().expect("thread");
        }
        assert!(peak.load(Ordering::Acquire) <= 4);
    }
}
