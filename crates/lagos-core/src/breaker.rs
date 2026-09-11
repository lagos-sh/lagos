//! Circuit breaker.
//!
//! ```yaml
//! upstreams:
//!   orders:
//!     url: http://orders:3000
//!     circuit_breaker:
//!       failures: 5
//!       window: 30s
//!       cooldown: 10s
//! ```
//!
//! # What this adds over health checks
//!
//! A pool `health_check` answers "is this backend up", and takes a dead one out
//! of rotation. A breaker answers a different question: "is this service
//! *working*". An upstream that accepts connections, passes its health probe,
//! and then returns 500s or takes 30 seconds to answer is invisible to a health
//! check and is exactly what a breaker is for.
//!
//! Opening also protects the upstream from the gateway. A service struggling
//! under load recovers faster if the traffic stops for ten seconds than if
//! every request keeps arriving and timing out — and requests that would have
//! queued behind a dead connection fail in microseconds instead of seconds.
//!
//! ```text
//!            failures within window
//!   CLOSED ────────────────────────▶ OPEN
//!      ▲                              │ cooldown elapses
//!      │ enough trials succeed        ▼
//!      └───────────────────────── HALF_OPEN
//!                                     │ any trial fails
//!                                     └──▶ OPEN
//! ```

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::CircuitBreakerConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Closed,
    Open,
    HalfOpen,
}

impl State {
    /// For the `gateway_circuit_state` gauge.
    pub fn as_metric(self) -> i64 {
        match self {
            Self::Closed => 0,
            Self::HalfOpen => 1,
            Self::Open => 2,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        }
    }
}

#[derive(Debug)]
struct Inner {
    state: State,
    /// Failures counted since `window_started`.
    failures: u32,
    window_started: Instant,
    /// When an open circuit may next admit a trial request.
    opened_at: Instant,
    /// Successful trials since entering half-open.
    trial_successes: u32,
    /// Trials currently allowed out. Bounded so a burst does not all rush a
    /// recovering upstream at once.
    trials_in_flight: u32,
}

pub struct CircuitBreaker {
    inner: Mutex<Inner>,
    failures: u32,
    window: Duration,
    cooldown: Duration,
    successes_to_close: u32,
    max_trials: u32,
}

impl std::fmt::Debug for CircuitBreaker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircuitBreaker")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl CircuitBreaker {
    pub fn new(cfg: &CircuitBreakerConfig) -> Self {
        let now = Instant::now();
        Self {
            inner: Mutex::new(Inner {
                state: State::Closed,
                failures: 0,
                window_started: now,
                opened_at: now,
                trial_successes: 0,
                trials_in_flight: 0,
            }),
            failures: cfg.failures,
            window: cfg.window,
            cooldown: cfg.cooldown,
            successes_to_close: cfg.successes_to_close,
            max_trials: cfg.max_trials,
        }
    }

    /// The critical section is a few integer comparisons with no await and no
    /// call into unknown code, so it cannot deadlock and cannot panic — which
    /// makes recovering a poisoned lock the right call rather than failing
    /// every request that touches this upstream.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub fn state(&self) -> State {
        self.lock().state
    }

    /// Whether to send this request upstream.
    ///
    /// Call once per request, before dialling. A `true` from a half-open
    /// circuit is a *trial*: the caller must report its outcome, or the circuit
    /// stays half-open forever.
    pub fn allow(&self) -> bool {
        self.allow_at(Instant::now())
    }

    fn allow_at(&self, now: Instant) -> bool {
        let mut inner = self.lock();
        match inner.state {
            State::Closed => true,
            State::Open => {
                if now.saturating_duration_since(inner.opened_at) < self.cooldown {
                    return false;
                }
                // Cooldown elapsed: admit a bounded number of trials to find
                // out whether the upstream has recovered.
                inner.state = State::HalfOpen;
                inner.trial_successes = 0;
                inner.trials_in_flight = 1;
                true
            }
            State::HalfOpen => {
                if inner.trials_in_flight >= self.max_trials {
                    // Everything else keeps failing fast while the trials run,
                    // so a recovering upstream is not hit by the full load the
                    // moment the cooldown ends.
                    return false;
                }
                inner.trials_in_flight = inner.trials_in_flight.saturating_add(1);
                true
            }
        }
    }

    pub fn record_success(&self) {
        self.record_success_at(Instant::now());
    }

    /// Release a trial that produced no upstream outcome, without counting
    /// it as evidence of either success or failure.
    pub fn cancel(&self) {
        let mut inner = self.lock();
        if inner.state == State::HalfOpen {
            inner.trials_in_flight = inner.trials_in_flight.saturating_sub(1);
        }
    }

    fn record_success_at(&self, _now: Instant) {
        let mut inner = self.lock();
        match inner.state {
            State::Closed => {
                // A success clears the run: `failures` within `window` means a
                // burst, not a total since the process started.
                inner.failures = 0;
            }
            State::HalfOpen => {
                inner.trials_in_flight = inner.trials_in_flight.saturating_sub(1);
                inner.trial_successes = inner.trial_successes.saturating_add(1);
                if inner.trial_successes >= self.successes_to_close {
                    inner.state = State::Closed;
                    inner.failures = 0;
                    inner.trial_successes = 0;
                    inner.trials_in_flight = 0;
                }
            }
            // A late success from a request that was in flight when the circuit
            // opened says nothing about the upstream's state now.
            State::Open => {}
        }
    }

    pub fn record_failure(&self) {
        self.record_failure_at(Instant::now());
    }

    fn record_failure_at(&self, now: Instant) {
        let mut inner = self.lock();
        match inner.state {
            State::Closed => {
                if now.saturating_duration_since(inner.window_started) > self.window {
                    inner.window_started = now;
                    inner.failures = 0;
                }
                inner.failures = inner.failures.saturating_add(1);
                if inner.failures >= self.failures {
                    inner.state = State::Open;
                    inner.opened_at = now;
                }
            }
            State::HalfOpen => {
                // One failed trial is enough: the upstream has not recovered.
                inner.state = State::Open;
                inner.opened_at = now;
                inner.trial_successes = 0;
                inner.trials_in_flight = 0;
            }
            State::Open => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failures: 3,
            window: Duration::from_secs(30),
            cooldown: Duration::from_secs(10),
            successes_to_close: 2,
            max_trials: 1,
        }
    }

    fn breaker() -> CircuitBreaker {
        CircuitBreaker::new(&cfg())
    }

    #[test]
    fn a_cancelled_trial_releases_its_slot_without_closing_the_circuit() {
        let b = breaker();
        let now = Instant::now();
        for _ in 0..3 {
            b.record_failure_at(now);
        }
        let trial_time = now + Duration::from_secs(11);
        assert!(b.allow_at(trial_time));
        assert!(!b.allow_at(trial_time));
        b.cancel();
        assert_eq!(b.state(), State::HalfOpen);
        assert!(b.allow_at(trial_time));
        b.record_success_at(trial_time);
        assert_eq!(
            b.state(),
            State::HalfOpen,
            "the cancelled trial was not a success"
        );
    }

    #[test]
    fn a_healthy_upstream_stays_closed() {
        let b = breaker();
        for _ in 0..100 {
            assert!(b.allow());
            b.record_success();
        }
        assert_eq!(b.state(), State::Closed);
    }

    #[test]
    fn enough_failures_open_the_circuit() {
        let b = breaker();
        for _ in 0..3 {
            assert!(b.allow());
            b.record_failure();
        }
        assert_eq!(b.state(), State::Open);
        assert!(!b.allow(), "an open circuit sheds load instead of dialling");
    }

    #[test]
    fn a_success_clears_the_failure_run() {
        // `failures within window` means a burst, not a lifetime total.
        let b = breaker();
        b.record_failure();
        b.record_failure();
        b.record_success();
        b.record_failure();
        b.record_failure();
        assert_eq!(b.state(), State::Closed, "the run was broken by a success");
    }

    #[test]
    fn failures_spread_beyond_the_window_do_not_open_it() {
        let b = breaker();
        let t0 = Instant::now();
        b.record_failure_at(t0);
        b.record_failure_at(t0 + Duration::from_secs(31));
        b.record_failure_at(t0 + Duration::from_secs(32));
        assert_eq!(
            b.state(),
            State::Closed,
            "the first failure aged out of the window"
        );
    }

    #[test]
    fn the_cooldown_must_elapse_before_a_trial() {
        let b = breaker();
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure_at(t0);
        }
        assert!(!b.allow_at(t0 + Duration::from_secs(9)));
        assert!(b.allow_at(t0 + Duration::from_secs(11)), "cooldown elapsed");
        assert_eq!(b.state(), State::HalfOpen);
    }

    #[test]
    fn a_recovering_upstream_closes_the_circuit() {
        let b = breaker();
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure_at(t0);
        }
        let later = t0 + Duration::from_secs(11);

        assert!(b.allow_at(later));
        b.record_success();
        assert_eq!(b.state(), State::HalfOpen, "one success is not enough");

        assert!(b.allow_at(later));
        b.record_success();
        assert_eq!(b.state(), State::Closed);
        assert!(b.allow_at(later));
    }

    #[test]
    fn a_failed_trial_reopens_immediately() {
        let b = breaker();
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure_at(t0);
        }
        let later = t0 + Duration::from_secs(11);
        assert!(b.allow_at(later));
        b.record_failure_at(later);
        assert_eq!(b.state(), State::Open);
        // And the cooldown restarts from the failed trial.
        assert!(!b.allow_at(later + Duration::from_secs(9)));
        assert!(b.allow_at(later + Duration::from_secs(11)));
    }

    #[test]
    fn half_open_admits_only_a_bounded_number_of_trials() {
        // Otherwise the full load arrives the instant the cooldown ends and
        // knocks the recovering upstream straight back over.
        let b = breaker();
        let t0 = Instant::now();
        for _ in 0..3 {
            b.record_failure_at(t0);
        }
        let later = t0 + Duration::from_secs(11);
        assert!(b.allow_at(later), "first trial");
        for _ in 0..50 {
            assert!(!b.allow_at(later), "further requests still fail fast");
        }
    }

    #[test]
    fn a_late_success_does_not_reopen_a_tripped_circuit() {
        // A request in flight when the circuit opened says nothing about now.
        let b = breaker();
        for _ in 0..3 {
            b.record_failure();
        }
        assert_eq!(b.state(), State::Open);
        b.record_success();
        assert_eq!(b.state(), State::Open);
    }
}
