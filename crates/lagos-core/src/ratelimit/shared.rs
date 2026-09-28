//! Cluster-wide counting: the bookkeeping half.
//!
//! [`SharedCounters`] holds, per key, what *this* replica has used and what the
//! others had used as of the last reconciliation. The request path reads that
//! and decides locally; a background task publishes the local delta and reads
//! the cluster's total back. Nothing here performs I/O — the RESP side is
//! [`Backend`], implemented in [`super::resp`] — which is what lets the
//! arithmetic below be tested against an adversarial clock and a failing
//! backend rather than against a server.
//!
//! # Windows are epoch-aligned here, and per-key locally
//!
//! The local limiter in [`super`] anchors each key's window at the moment that
//! key was first seen. That is the better behaviour for counting inside one
//! process — the window starts when the caller does — but it is useless across
//! replicas, because no two of them agree on where a window begins and their
//! counts cannot be added together.
//!
//! So a shared window is indexed by `unix_nanos / interval`, which every replica
//! computes identically. The price is that this arithmetic now rests on the wall
//! clock: replicas whose clocks differ by `d` disagree about where the boundary
//! falls by `d`, and an NTP step moves the boundary under them. Neither breaks a
//! limit — a request is always counted into *some* bucket exactly once, and the
//! sliding weight means no boundary is a cliff — it only blurs which bucket.
//! Skew beyond a full interval is the point where the previous-window weighting
//! stops meaning much, which is why `interval` is required to be at least a
//! second and why an operator running without NTP should prefer `exact`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use super::Decision;

/// Which epoch-aligned window a moment falls in, and how far through it.
///
/// `None` when the interval is zero or the clock is before 1970 — neither is
/// reachable from a validated config, and both would otherwise divide by zero
/// or wrap.
fn position(now: SystemTime, interval: Duration) -> Option<(u64, f64)> {
    let elapsed = now.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_nanos();
    let width = interval.as_nanos();
    if width == 0 {
        return None;
    }
    // Integer division for the index, so the bucket a replica computes is exact
    // rather than whatever a float happened to round to near a boundary. Only
    // the fraction within the bucket becomes a float, where it is compared, not
    // used as an identity.
    let bucket = u64::try_from(elapsed / width).ok()?;
    let progress = ((elapsed % width) as f64) / (width as f64);
    Some((bucket, progress.clamp(0.0, 1.0)))
}

/// One key's cluster view.
#[derive(Debug, Default)]
struct Shard {
    /// Distinguishes an evicted/reloaded key from an older incarnation.
    source: uuid::Uuid,
    /// The epoch bucket `current` counts belong to.
    bucket: u64,
    /// This replica, this bucket and the one before.
    own_current: u64,
    own_previous: u64,
    /// Every other replica, as of the last successful reconciliation.
    remote_current: u64,
    remote_previous: u64,
    /// Usage assigned to immutable publications, including the retry batch.
    /// Reserving it prevents a later snapshot from publishing the same usage
    /// under a different ID while the original answer is still uncertain.
    published: u64,
    published_previous: u64,
}

impl Shard {
    /// Bring `self` up to `bucket`, carrying what is still in view.
    fn roll_to(&mut self, bucket: u64) {
        if bucket <= self.bucket {
            // Equal is the common case. Less than means the wall clock stepped
            // backwards; the counts are still this replica's own and the safe
            // reading is to keep them rather than hand out a fresh quota.
            return;
        }
        if bucket == self.bucket.saturating_add(1) {
            self.own_previous = self.own_current;
            self.remote_previous = self.remote_current;
            self.published_previous = self.published;
        } else {
            // Two or more buckets idle: nothing from before is in view.
            self.own_previous = 0;
            self.remote_previous = 0;
            self.published_previous = 0;
        }
        self.own_current = 0;
        self.remote_current = 0;
        self.published = 0;
        self.bucket = bucket;
    }
}

/// What one key owes the cluster, and what is needed to interpret the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    /// Immutable contribution ID. A retry must reuse this ID and its deltas.
    pub id: uuid::Uuid,
    /// The local key incarnation that produced this snapshot.
    pub source: uuid::Uuid,
    /// The cache key, prefix already applied.
    pub key: String,
    /// Bucket the delta belongs to.
    pub bucket: u64,
    /// Requests this replica has served in `bucket` and not yet published.
    pub delta: u64,
    /// Unpublished usage still contributing from the previous bucket.
    pub delta_previous: u64,
    /// This replica's own total for `bucket` at the moment of the snapshot, so
    /// its contribution can be subtracted from the cluster total.
    pub own_current: u64,
    /// The same for the previous bucket.
    pub own_previous: u64,
    /// The window width this key is counted over.
    ///
    /// Carried per key rather than held by the backend because one backend
    /// serves every route, and two routes may well count over different
    /// intervals. It is what sets the counter's TTL, so a backend that assumed
    /// a single interval would expire one route's window on another route's
    /// schedule.
    pub interval: Duration,
}

/// The cluster totals a reconciliation read back, this replica included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Totals {
    pub current: u64,
    pub previous: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("shared counter backend unreachable: {0}")]
    Unavailable(String),
    #[error("shared counter backend timed out after {0:?}")]
    Timeout(Duration),
    #[error("shared counter backend replied with something unreadable: {0}")]
    Protocol(String),
}

/// The RESP half of shared counting.
///
/// A trait for two reasons: it keeps the `redis` dependency behind one feature
/// gate, and it lets the bookkeeping above be tested against a backend that
/// returns whatever a test needs — including failures, which are the branch that
/// actually matters.
#[async_trait::async_trait]
pub trait Backend: Send + Sync + std::fmt::Debug {
    /// Publish each entry's deltas idempotently and read cluster totals back.
    /// Repeating an ID must never add its contribution a second time.
    ///
    /// The reply must be positionally aligned with `batch`; a backend that
    /// cannot honour that must return `Err` rather than a short vector.
    async fn reconcile(&self, batch: &[Publish]) -> Result<Vec<Totals>, BackendError>;

    /// One authoritative decision, for [`crate::config::LimitMode::Exact`].
    async fn check_exact(
        &self,
        key: &str,
        limit: u64,
        interval: Duration,
    ) -> Result<Decision, BackendError>;

    /// Identify the server, and say whether it can serve
    /// [`crate::config::LimitMode::Exact`].
    ///
    /// The one call that requires the backend to be reachable. Made once at
    /// startup, so a config asking for exactness from a server that cannot
    /// provide it is a boot error naming the problem rather than a limit that
    /// silently never applied.
    async fn probe(&self) -> Result<(String, bool), BackendError>;
}

/// Per-key cluster state, plus the backend that reconciles it.
pub struct SharedCounters {
    shards: moka::sync::Cache<String, Arc<Mutex<Shard>>>,
    backend: Arc<dyn Backend>,
    prefix: String,
    interval: Duration,
    limit: u64,
    batch: usize,
    scan_after: Mutex<Option<Arc<String>>>,
    retry: Mutex<Vec<Publish>>,
    sync_lock: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for SharedCounters {
    /// Opaque for the same reason [`super::Limiter`]'s is: the contents are
    /// per-caller counters and a route's `Debug` ends up in logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedCounters")
            .field("limit", &self.limit)
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

impl SharedCounters {
    pub fn new(
        cfg: &crate::config::RateLimitConfig,
        shared: &crate::config::SharedCountersConfig,
        backend: Arc<dyn Backend>,
    ) -> Self {
        Self {
            shards: moka::sync::Cache::builder()
                .max_capacity(cfg.max_keys)
                // Two buckets is as far back as the estimate can see, matching
                // the local store's reasoning and the TTL written to the cache.
                .time_to_idle(cfg.interval.saturating_mul(2))
                .build(),
            backend,
            prefix: shared.prefix.clone(),
            interval: cfg.interval,
            limit: cfg.requests,
            batch: shared.max_keys_per_sync,
            scan_after: Mutex::new(None),
            retry: Mutex::new(Vec::new()),
            sync_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Decide, using the cluster view as of the last reconciliation.
    ///
    /// No I/O and no await: the whole point of the approximate mode is that a
    /// request never waits on the cache. Capped batches and backend latency can
    /// make the reconciliation period longer than the configured tick interval.
    pub fn check_at(&self, key: &str, now: SystemTime) -> Decision {
        let Some((bucket, progress)) = position(now, self.interval) else {
            // An interval a validated config cannot produce. Refusing every
            // request over a arithmetic edge case would be a worse failure than
            // not limiting, and the local limiter is still in front of this.
            return Decision::allow(self.limit, self.limit.saturating_sub(1));
        };

        let shard = self.shards.get_with_by_ref(key, || {
            Arc::new(Mutex::new(Shard {
                source: uuid::Uuid::new_v4(),
                ..Shard::default()
            }))
        });

        // A few integer operations, no await inside, and no call into code this
        // module does not own -- so it cannot deadlock and cannot poison. A
        // poisoned lock is recovered rather than propagated for the same reason
        // the local limiter does it: keeping the limit working beats failing
        // every request that happens to share a key.
        let mut shard = match shard.lock() {
            Ok(s) => s,
            Err(poisoned) => poisoned.into_inner(),
        };
        shard.roll_to(bucket);

        let previous = shard.own_previous.saturating_add(shard.remote_previous);
        let current = shard.own_current.saturating_add(shard.remote_current);
        let decision = super::decide(previous, current, progress, self.limit, self.interval);
        if decision.allowed {
            shard.own_current = shard.own_current.saturating_add(1);
        }
        decision
    }

    /// Ask the backend outright. `None` when it could not answer, which the
    /// caller answers locally instead.
    pub async fn check_exact(&self, key: &str) -> Option<Decision> {
        match self
            .backend
            .check_exact(&self.cache_key(key), self.limit, self.interval)
            .await
        {
            Ok(decision) => Some(decision),
            Err(e) => {
                // Deliberately not per-request logging: a cache outage would
                // otherwise turn every limited request into a log line, which
                // is its own outage. The counter is the signal to alert on.
                tracing::debug!(error = %e, "shared rate-limit check failed; deciding locally");
                if let Some(m) = crate::metrics::metrics() {
                    m.shared_limit_error();
                }
                None
            }
        }
    }

    fn cache_key(&self, key: &str) -> String {
        format!("{}{}", self.prefix, key)
    }

    /// Snapshot what every tracked key owes the cluster.
    ///
    /// Capped at `max_keys_per_sync`: the local store is bounded, but a tick
    /// that cannot finish inside its own interval is a queue that grows, and
    /// leaving keys to the next tick costs accuracy rather than correctness.
    pub fn pending(&self, now: SystemTime) -> Vec<Publish> {
        let Some((bucket, _)) = position(now, self.interval) else {
            return Vec::new();
        };
        // Stable ordering plus a cursor ensures capped ticks visit every key.
        // Iteration does not refresh Moka's request-driven idle timers.
        let mut entries: Vec<_> = self.shards.iter().collect();
        entries.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        let mut cursor = self.scan_after.lock().unwrap_or_else(|p| p.into_inner());
        let start = cursor
            .as_ref()
            .map_or(0, |last| entries.partition_point(|(key, _)| key <= last));
        let (before, after) = entries.split_at(start);
        let mut out = Vec::new();
        for (key, shard) in after.iter().chain(before).take(self.batch) {
            let mut shard = match shard.lock() {
                Ok(s) => s,
                Err(poisoned) => poisoned.into_inner(),
            };
            shard.roll_to(bucket);
            let delta = shard.own_current.saturating_sub(shard.published);
            let delta_previous = shard.own_previous.saturating_sub(shard.published_previous);
            // Reserve both deltas. Failed syncs retry the identical contribution
            // rather than creating a second contribution for the same usage.
            shard.published = shard.own_current;
            shard.published_previous = shard.own_previous;
            out.push(Publish {
                id: uuid::Uuid::new_v4(),
                source: shard.source,
                key: self.cache_key(key),
                bucket: shard.bucket,
                delta,
                delta_previous,
                own_current: shard.own_current,
                own_previous: shard.own_previous,
                interval: self.interval,
            });
            *cursor = Some(key.clone());
        }
        out
    }

    /// Fold reconciled totals back into the cluster view.
    ///
    /// `totals` must be positionally aligned with `batch`; a mismatched pair is
    /// ignored rather than misapplied, since attributing one key's usage to
    /// another would throttle an innocent caller.
    pub fn apply(&self, batch: &[Publish], totals: &[Totals]) {
        if batch.len() != totals.len() {
            tracing::warn!(
                sent = batch.len(),
                received = totals.len(),
                "shared rate-limit reconciliation came back misaligned; discarding"
            );
            return;
        }
        // Look up snapshots through iteration: maintenance must not count as
        // caller activity and extend a key's idle lifetime.
        let wanted: HashMap<_, _> = batch
            .iter()
            .zip(totals)
            .map(|(p, t)| (strip(&p.key, &self.prefix), (p, t)))
            .collect();
        for (key, shard) in self.shards.iter() {
            let Some((publish, total)) = wanted.get(key.as_str()) else {
                // Evicted mid-tick. Nothing to update and nothing lost.
                continue;
            };
            let mut shard = match shard.lock() {
                Ok(s) => s,
                Err(poisoned) => poisoned.into_inner(),
            };
            if shard.source != publish.source {
                continue;
            }
            if shard.bucket == publish.bucket.saturating_add(1) {
                // A response crossing the boundary still describes the window
                // now used as previous; keep that contribution in view.
                shard.remote_previous = total.current.saturating_sub(publish.own_current);
                continue;
            }
            if shard.bucket != publish.bucket {
                // Rolled while the round trip was in flight, so these totals
                // describe a window that is no longer current. The next tick
                // reads the right one; applying these would count the old
                // bucket's traffic against the new one's quota.
                continue;
            }
            // The cluster total includes this replica's own published
            // contribution, so subtract it to get everyone else. Saturating
            // because another replica's view can lag this one's and a wrapped
            // subtraction here would read as a near-infinite remote count and
            // refuse everything.
            shard.remote_current = total.current.saturating_sub(publish.own_current);
            shard.remote_previous = total.previous.saturating_sub(publish.own_previous);
        }
    }

    /// Reconcile once. Called by the background task, never from a request.
    pub async fn sync_once(&self, now: SystemTime) {
        // Serialize snapshots and retries, including calls from other runtimes.
        let _sync = self.sync_lock.lock().await;
        let mut batch = {
            let mut retry = self.retry.lock().unwrap_or_else(|p| p.into_inner());
            std::mem::take(&mut *retry)
        };
        if let Some((bucket, _)) = position(now, self.interval) {
            batch.retain(|p| p.bucket.saturating_add(1) >= bucket);
        }
        if batch.is_empty() {
            batch = self.pending(now);
        }
        if batch.is_empty() {
            return;
        }
        match self.backend.reconcile(&batch).await {
            Ok(totals) if totals.len() == batch.len() => {
                self.apply(&batch, &totals);
                if let Some(m) = crate::metrics::metrics() {
                    m.shared_limit_synced(batch.len() as u64);
                }
            }
            result => {
                // Accuracy degrades to whatever this replica last knew; the
                // local half of the estimate keeps limiting. Republish the
                // delta next tick rather than dropping it on the floor.
                let error = match result {
                    Err(e) => e,
                    Ok(_) => BackendError::Protocol("misaligned reconciliation".into()),
                };
                tracing::warn!(%error, keys = batch.len(), "shared rate-limit sync failed");
                if let Some(m) = crate::metrics::metrics() {
                    m.shared_limit_error();
                }
                *self.retry.lock().unwrap_or_else(|p| p.into_inner()) = batch;
            }
        }
    }

    /// Keys currently tracked. Mirrors [`super::Limiter::tracked`].
    pub fn tracked(&self) -> u64 {
        self.shards.run_pending_tasks();
        self.shards.entry_count()
    }
}

/// Undo [`SharedCounters::cache_key`].
fn strip<'a>(key: &'a str, prefix: &str) -> &'a str {
    key.strip_prefix(prefix).unwrap_or(key)
}

/// One backend connection plus its settings, cloned into every route that opts
/// in.
///
/// The connection is shared across routes; the per-key state is not. Two routes
/// with the same limit definition still get separate counters, because keys are
/// route-scoped and a quota spent on one route must not spend another's.
#[derive(Clone)]
pub struct SharedCounterFactory {
    backend: Arc<dyn Backend>,
    cfg: Arc<crate::config::SharedCountersConfig>,
}

impl std::fmt::Debug for SharedCounterFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedCounterFactory")
            // Redacted: the url carries the cache password about as often as
            // not, and a factory reachable from a route's `Debug` ends up in
            // logs.
            .field("url", &redact_url(&self.cfg.url))
            .field("sync", &self.cfg.sync)
            .finish_non_exhaustive()
    }
}

impl SharedCounterFactory {
    pub fn new(backend: Arc<dyn Backend>, cfg: crate::config::SharedCountersConfig) -> Self {
        Self {
            backend,
            cfg: Arc::new(cfg),
        }
    }

    pub fn build(&self, rl: &crate::config::RateLimitConfig) -> Arc<SharedCounters> {
        Arc::new(SharedCounters::new(rl, &self.cfg, self.backend.clone()))
    }

    pub fn sync_interval(&self) -> Duration {
        self.cfg.sync
    }

    /// See [`Backend::probe`].
    pub async fn probe(&self) -> Result<(String, bool), BackendError> {
        self.backend.probe().await
    }
}

/// Schemes accepted for a shared-counter URL.
///
/// `redis` and `rediss` are the protocol's own URL schemes and are what every
/// RESP client parses, so they are accepted whatever is actually listening. The
/// rest are aliases mapping onto them, so a configuration need not name a
/// product the operator does not run -- a gateway in front of Recached should
/// not have to write `redis://` to reach it.
const SCHEMES: &[(&str, &str)] = &[
    ("recached://", "redis://"),
    ("recacheds://", "rediss://"),
    ("valkey://", "redis://"),
    ("valkeys://", "rediss://"),
    ("resp://", "redis://"),
    ("resps://", "rediss://"),
    ("redis://", "redis://"),
    ("rediss://", "rediss://"),
];

/// Rewrite an accepted alias to the scheme a RESP client understands.
///
/// `Err` names what was accepted rather than echoing the whole URL back, which
/// would put a password in a startup error and from there into a log.
pub fn normalize_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    for (alias, canonical) in SCHEMES {
        if let Some(rest) = trimmed.strip_prefix(alias) {
            if rest.is_empty() {
                return Err(format!("`{alias}` with no host"));
            }
            return Ok(format!("{canonical}{rest}"));
        }
    }
    let scheme = trimmed
        .split_once("://")
        .map(|(s, _)| s)
        .unwrap_or("(none)");
    Err(format!(
        "`{scheme}` is not a shared-counter scheme; expected one of \
         recached, valkey, resp or redis, each optionally with a trailing \
         `s` for TLS"
    ))
}

/// A URL with its password replaced, for logs, errors and `Debug`.
///
/// **The `@` is located before the path delimiters, not after.** An authority
/// ends at the first `/`, `?` or `#` per RFC 3986, so splitting on those first
/// cuts a URL whose *password* contains one in the middle of that password --
/// the `@` then goes missing and the whole URL, password included, is handed
/// back untouched. Managed caches issue base64 passwords, so a literal `/` in
/// one is ordinary rather than exotic.
///
/// **Ambiguity redacts more, never less.** A URL that cannot be split
/// confidently loses its whole userinfo rather than part of it. That
/// over-redacts the rare URL with an `@` in its path and no credentials at all;
/// printing `***` for something that was never secret is the only direction of
/// error this function is allowed to make.
pub fn redact_url(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => match redact_authority(rest) {
            Some(masked) => format!("{scheme}://{masked}"),
            None => url.to_string(),
        },
        // No scheme is not a promise there are no credentials: `user:pass@host`
        // is an ordinary thing to find in a config file.
        None => redact_authority(url).unwrap_or_else(|| url.to_string()),
    }
}

/// Mask the password in `<userinfo>@<host><suffix>`, or `None` when there is
/// nothing to mask.
fn redact_authority(rest: &str) -> Option<String> {
    // Last `@`, so a password containing one still lands on the correct side of
    // the split.
    let at = rest.rfind('@')?;
    let (credentials, tail) = rest.split_at(at);
    let host = tail.strip_prefix('@')?;
    // A username with no password is not a secret.
    let (username, _password) = credentials.split_once(':')?;
    if username.contains(['/', '?', '#']) {
        // The split landed past a path delimiter, so this is not a userinfo
        // that can be read. Whatever it is, the password is inside it.
        Some(format!("***@{host}"))
    } else {
        Some(format!("{username}:***@{host}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A backend that answers from an in-memory cluster total, so the
    /// bookkeeping can be driven without a server.
    #[derive(Debug, Default)]
    struct FakeBackend {
        /// `key:bucket` -> cluster total.
        totals: Mutex<std::collections::HashMap<String, u64>>,
        calls: AtomicU64,
        applied: Mutex<std::collections::HashSet<(String, u64, uuid::Uuid)>>,
        lose_reply: std::sync::atomic::AtomicBool,
        fail: std::sync::atomic::AtomicBool,
    }

    impl FakeBackend {
        /// Pretend another replica served `n` requests for `key` in `bucket`.
        fn add_remote(&self, key: &str, bucket: u64, n: u64) {
            *self
                .totals
                .lock()
                .unwrap()
                .entry(format!("{key}:{bucket}"))
                .or_insert(0) += n;
        }
    }

    #[async_trait::async_trait]
    impl Backend for FakeBackend {
        async fn reconcile(&self, batch: &[Publish]) -> Result<Vec<Totals>, BackendError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.fail.load(Ordering::Relaxed) {
                return Err(BackendError::Unavailable("test".into()));
            }
            let mut totals = self.totals.lock().unwrap();
            let mut applied = self.applied.lock().unwrap();
            let result = batch
                .iter()
                .map(|p| {
                    for (bucket, delta) in [
                        (p.bucket, p.delta),
                        (p.bucket.saturating_sub(1), p.delta_previous),
                    ] {
                        if delta != 0 && applied.insert((p.key.clone(), bucket, p.id)) {
                            *totals.entry(format!("{}:{bucket}", p.key)).or_insert(0) += delta;
                        }
                    }
                    Totals {
                        current: totals
                            .get(&format!("{}:{}", p.key, p.bucket))
                            .copied()
                            .unwrap_or(0),
                        previous: p
                            .bucket
                            .checked_sub(1)
                            .and_then(|b| totals.get(&format!("{}:{b}", p.key)).copied())
                            .unwrap_or(0),
                    }
                })
                .collect();
            if self.lose_reply.swap(false, Ordering::Relaxed) {
                Err(BackendError::Timeout(Duration::from_millis(250)))
            } else {
                Ok(result)
            }
        }

        async fn check_exact(
            &self,
            _key: &str,
            limit: u64,
            _interval: Duration,
        ) -> Result<Decision, BackendError> {
            if self.fail.load(Ordering::Relaxed) {
                return Err(BackendError::Unavailable("test".into()));
            }
            Ok(Decision::allow(limit, 7))
        }

        async fn probe(&self) -> Result<(String, bool), BackendError> {
            if self.fail.load(Ordering::Relaxed) {
                return Err(BackendError::Unavailable("test".into()));
            }
            Ok(("a test double".into(), true))
        }
    }

    fn counters(requests: u64, backend: Arc<FakeBackend>) -> SharedCounters {
        counters_with(requests, Duration::from_secs(60), 4096, backend)
    }

    fn counters_with(
        requests: u64,
        interval: Duration,
        batch: usize,
        backend: Arc<FakeBackend>,
    ) -> SharedCounters {
        let cfg = crate::config::RateLimitConfig {
            requests,
            interval,
            key: crate::config::RateLimitKey::Ip,
            trusted_proxies: 0,
            max_keys: 1000,
            counter: crate::config::Counter::Shared,
            mode: crate::config::LimitMode::Approximate,
        };
        let shared = crate::config::SharedCountersConfig {
            url: "recached://localhost:6379".into(),
            sync: Duration::from_secs(1),
            prefix: "t:".into(),
            timeout: Duration::from_millis(250),
            max_keys_per_sync: batch,
        };
        SharedCounters::new(&cfg, &shared, backend)
    }

    /// A moment far enough into a bucket that a test can move within it.
    fn mid_bucket() -> SystemTime {
        let interval = Duration::from_secs(60);
        let now = SystemTime::now();
        let (bucket, _) = position(now, interval).unwrap();
        SystemTime::UNIX_EPOCH + interval * u32::try_from(bucket).unwrap() + interval / 2
    }

    #[test]
    fn every_replica_agrees_on_the_window() {
        // The property the whole design rests on: two replicas computing a
        // bucket for the same instant must get the same number, or their counts
        // cannot be added together at all.
        let interval = Duration::from_secs(60);
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_037);
        let a = position(t, interval).unwrap();
        let b = position(t, interval).unwrap();
        assert_eq!(a.0, b.0);
        assert_eq!(a.0, 16_666_667);
        // Bucket 16,666,667 starts at 1,000,000,020s, so that instant is 17s
        // into a 60s window -- not 37s, which is where the *minute* boundary
        // would put it. Window boundaries are multiples of the interval from
        // the epoch, not wall-clock minutes.
        assert!((a.1 - 17.0 / 60.0).abs() < 1e-9, "progress was {}", a.1);
    }

    #[test]
    fn a_zero_interval_cannot_divide_by_zero() {
        assert!(position(SystemTime::now(), Duration::ZERO).is_none());
    }

    #[tokio::test]
    async fn another_replicas_usage_is_counted_against_the_limit() {
        // The bug this whole feature exists to fix: without the shared view
        // this replica would admit all 10 of its own.
        let backend = Arc::new(FakeBackend::default());
        let c = counters(10, backend.clone());
        let now = mid_bucket();
        let (bucket, _) = position(now, Duration::from_secs(60)).unwrap();

        // Two other replicas have already spent 8 of the 10.
        backend.add_remote("t:k", bucket, 8);
        c.check_at("k", now); // creates the shard so the sync sees it
        c.sync_once(now).await;

        let granted = (0..10).filter(|_| c.check_at("k", now).allowed).count();
        assert_eq!(
            granted, 1,
            "8 spent elsewhere plus 1 already counted here leaves 1, got {granted}"
        );
    }

    #[tokio::test]
    async fn this_replica_is_not_throttled_by_its_own_published_traffic() {
        // The mistake that makes a shared limiter useless: read the cluster
        // total back and count your own contribution twice.
        let backend = Arc::new(FakeBackend::default());
        let c = counters(10, backend.clone());
        let now = mid_bucket();

        for _ in 0..5 {
            assert!(c.check_at("k", now).allowed);
        }
        // Several reconciliations with nobody else on the cluster.
        for _ in 0..4 {
            c.sync_once(now).await;
        }
        let granted = (0..10).filter(|_| c.check_at("k", now).allowed).count();
        assert_eq!(
            granted, 5,
            "5 used and no other replica means 5 left however often we sync, got {granted}"
        );
    }

    #[tokio::test]
    async fn a_delta_is_published_exactly_once() {
        let backend = Arc::new(FakeBackend::default());
        let c = counters(1000, backend.clone());
        let now = mid_bucket();
        let (bucket, _) = position(now, Duration::from_secs(60)).unwrap();

        for _ in 0..7 {
            c.check_at("k", now);
        }
        c.sync_once(now).await;
        c.sync_once(now).await;
        c.sync_once(now).await;

        assert_eq!(
            backend.totals.lock().unwrap().get(&format!("t:k:{bucket}")),
            Some(&7),
            "7 requests must reach the cluster as 7, not 21"
        );
    }

    #[tokio::test]
    async fn a_failed_sync_still_owes_its_delta() {
        // Otherwise an outage silently forgives whatever was in flight, and the
        // cluster undercounts for good.
        let backend = Arc::new(FakeBackend::default());
        let c = counters(1000, backend.clone());
        let now = mid_bucket();
        let (bucket, _) = position(now, Duration::from_secs(60)).unwrap();

        for _ in 0..4 {
            c.check_at("k", now);
        }
        backend.fail.store(true, Ordering::Relaxed);
        c.sync_once(now).await;
        backend.fail.store(false, Ordering::Relaxed);
        c.sync_once(now).await;

        assert_eq!(
            backend.totals.lock().unwrap().get(&format!("t:k:{bucket}")),
            Some(&4),
            "the delta the failed tick held must be republished, not dropped"
        );
    }

    #[tokio::test]
    async fn rollover_publishes_outstanding_previous_usage() {
        let backend = Arc::new(FakeBackend::default());
        let c = counters(10, backend.clone());
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(119);
        for _ in 0..4 {
            assert!(c.check_at("k", start).allowed);
        }
        c.sync_once(start).await;
        for _ in 0..6 {
            assert!(c.check_at("k", start).allowed);
        }
        let next = start + Duration::from_secs(1);
        c.sync_once(next).await;
        assert_eq!(backend.totals.lock().unwrap().get("t:k:1"), Some(&10));

        let replica = counters(10, backend);
        replica.check_at("k", next);
        replica.sync_once(next).await;
        assert!(!replica.check_at("k", next).allowed);
    }

    #[tokio::test]
    async fn a_lost_reply_retries_the_same_contribution_across_rollover() {
        let backend = Arc::new(FakeBackend::default());
        let c = counters(10, backend.clone());
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(119);
        for _ in 0..5 {
            c.check_at("k", now);
        }
        backend.lose_reply.store(true, Ordering::Relaxed);
        c.sync_once(now).await;
        // More usage arrives while the first contribution's outcome is unknown.
        for _ in 0..2 {
            c.check_at("k", now);
        }
        c.sync_once(now + Duration::from_secs(1)).await;
        c.sync_once(now + Duration::from_secs(1)).await;
        assert_eq!(backend.totals.lock().unwrap().get("t:k:1"), Some(&7));
        // Retry must not attribute this replica's own duplicate to a peer.
        let granted = (0..10)
            .filter(|_| c.check_at("k", now + Duration::from_secs(1)).allowed)
            .count();
        assert_eq!(granted, 3);
    }

    #[tokio::test]
    async fn capped_ticks_reconcile_all_keys_and_continue_after_wraparound() {
        let backend = Arc::new(FakeBackend::default());
        let c = counters_with(10, Duration::from_secs(60), 2, backend.clone());
        let now = mid_bucket();
        let (bucket, _) = position(now, Duration::from_secs(60)).unwrap();
        for i in 0..20 {
            c.check_at(&format!("k-{i}"), now);
        }
        c.tracked();
        for _ in 0..10 {
            c.sync_once(now).await;
        }
        for i in 0..20 {
            assert_eq!(
                backend
                    .totals
                    .lock()
                    .unwrap()
                    .get(&format!("t:k-{i}:{bucket}")),
                Some(&1)
            );
            backend.add_remote(&format!("t:k-{i}"), bucket, 9);
        }
        // Keys with no new local usage still need their remote totals refreshed.
        for _ in 0..10 {
            c.sync_once(now).await;
        }
        for i in 0..20 {
            assert!(!c.check_at(&format!("k-{i}"), now).allowed);
        }
    }

    #[tokio::test]
    async fn background_sync_does_not_extend_request_idle_expiry() {
        let c = counters_with(
            10,
            Duration::from_secs(1),
            2,
            Arc::new(FakeBackend::default()),
        );
        c.check_at("k", SystemTime::now());
        c.tracked();
        for _ in 0..15 {
            c.sync_once(SystemTime::now()).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert_eq!(c.tracked(), 0);
    }

    #[test]
    fn a_boundary_crossing_reply_updates_the_previous_window() {
        let c = counters(10, Arc::new(FakeBackend::default()));
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(119);
        c.check_at("k", now);
        let batch = c.pending(now);
        let next = now + Duration::from_secs(1);
        c.check_at("k", next);
        c.apply(
            &batch,
            &[Totals {
                current: 10,
                previous: 0,
            }],
        );
        assert!(!c.check_at("k", next).allowed);
    }

    #[test]
    fn a_reply_cannot_update_a_recreated_key() {
        let c = counters(10, Arc::new(FakeBackend::default()));
        let now = mid_bucket();
        c.check_at("k", now);
        let batch = c.pending(now);
        c.shards.invalidate("k");
        c.check_at("k", now);
        c.apply(
            &batch,
            &[Totals {
                current: 10,
                previous: 0,
            }],
        );
        assert!(c.check_at("k", now).allowed);
    }

    #[tokio::test]
    async fn an_unreachable_backend_keeps_limiting_locally() {
        // The roadmap's hard rule: traffic continues when the shared store does
        // not. Degraded to per-process counting is the correct failure.
        let backend = Arc::new(FakeBackend::default());
        backend.fail.store(true, Ordering::Relaxed);
        let c = counters(3, backend.clone());
        let now = mid_bucket();

        for i in 0..3 {
            assert!(c.check_at("k", now).allowed, "request {i}");
        }
        assert!(
            !c.check_at("k", now).allowed,
            "the local half of the estimate must still hold the limit"
        );
    }

    #[tokio::test]
    async fn an_exact_check_falls_back_when_the_backend_is_down() {
        let backend = Arc::new(FakeBackend::default());
        let c = counters(10, backend.clone());
        assert!(c.check_exact("k").await.is_some());
        backend.fail.store(true, Ordering::Relaxed);
        assert!(
            c.check_exact("k").await.is_none(),
            "an unanswerable check must defer to the local decision, not refuse"
        );
    }

    #[tokio::test]
    async fn totals_that_do_not_line_up_are_discarded() {
        // Attributing one key's usage to another would refuse an innocent
        // caller, which is worse than losing a tick of accuracy.
        let backend = Arc::new(FakeBackend::default());
        let c = counters(10, backend);
        let now = mid_bucket();
        c.check_at("a", now);
        c.check_at("b", now);

        let batch = c.pending(now);
        assert_eq!(batch.len(), 2);
        c.apply(
            &batch,
            &[Totals {
                current: 9,
                previous: 0,
            }],
        );

        let granted = (0..10).filter(|_| c.check_at("a", now).allowed).count();
        assert_eq!(granted, 9, "the bogus reply must not have been applied");
    }

    #[tokio::test]
    async fn totals_for_a_window_that_has_rolled_are_discarded() {
        let backend = Arc::new(FakeBackend::default());
        let c = counters(10, backend);
        let interval = Duration::from_secs(60);
        let now = mid_bucket();
        c.check_at("k", now);

        let mut batch = c.pending(now);
        // Pretend the round trip was slow enough for the window to move on.
        for p in &mut batch {
            p.bucket = p.bucket.saturating_sub(1);
            p.own_current = 0;
        }
        c.apply(
            &batch,
            &[Totals {
                current: 10,
                previous: 0,
            }],
        );

        assert!(
            c.check_at("k", now + interval / 10).allowed,
            "a stale window's totals must not spend the current window's quota"
        );
    }

    #[test]
    fn an_idle_window_releases_the_whole_quota() {
        let backend = Arc::new(FakeBackend::default());
        let c = counters(2, backend);
        let interval = Duration::from_secs(60);
        let now = mid_bucket();
        assert!(c.check_at("k", now).allowed);
        assert!(c.check_at("k", now).allowed);
        assert!(!c.check_at("k", now).allowed);
        assert!(
            c.check_at("k", now + interval * 2).allowed,
            "two buckets on, nothing earlier is in view"
        );
    }

    #[test]
    fn a_backwards_clock_step_does_not_mint_a_fresh_quota() {
        // NTP correcting a fast clock must not read as "new window, full quota".
        let backend = Arc::new(FakeBackend::default());
        let c = counters(2, backend);
        let interval = Duration::from_secs(60);
        let now = mid_bucket();
        assert!(c.check_at("k", now).allowed);
        assert!(c.check_at("k", now).allowed);
        assert!(!c.check_at("k", now).allowed);
        assert!(
            !c.check_at("k", now - interval * 3).allowed,
            "stepping the clock back must not hand out the quota again"
        );
    }

    #[test]
    fn the_store_is_bounded() {
        // Keys come from requests, so this is the memory-exhaustion guard.
        let backend = Arc::new(FakeBackend::default());
        let mut cfg = crate::config::RateLimitConfig {
            requests: 10,
            interval: Duration::from_secs(60),
            key: crate::config::RateLimitKey::Ip,
            trusted_proxies: 0,
            max_keys: 10,
            counter: crate::config::Counter::Shared,
            mode: crate::config::LimitMode::Approximate,
        };
        cfg.max_keys = 10;
        let shared = crate::config::SharedCountersConfig {
            url: "recached://localhost:6379".into(),
            sync: Duration::from_secs(1),
            prefix: "t:".into(),
            timeout: Duration::from_millis(250),
            max_keys_per_sync: 4096,
        };
        let c = SharedCounters::new(&cfg, &shared, backend);
        let now = mid_bucket();
        for i in 0..500 {
            c.check_at(&format!("key-{i}"), now);
        }
        assert!(
            c.tracked() <= 20,
            "a flood of distinct keys must not grow the process, got {}",
            c.tracked()
        );
    }

    #[test]
    fn a_tick_is_capped_so_it_can_finish() {
        let backend = Arc::new(FakeBackend::default());
        let cfg = crate::config::RateLimitConfig {
            requests: 10,
            interval: Duration::from_secs(60),
            key: crate::config::RateLimitKey::Ip,
            trusted_proxies: 0,
            max_keys: 10_000,
            counter: crate::config::Counter::Shared,
            mode: crate::config::LimitMode::Approximate,
        };
        let shared = crate::config::SharedCountersConfig {
            url: "recached://localhost:6379".into(),
            sync: Duration::from_secs(1),
            prefix: "t:".into(),
            timeout: Duration::from_millis(250),
            max_keys_per_sync: 25,
        };
        let c = SharedCounters::new(&cfg, &shared, backend);
        let now = mid_bucket();
        for i in 0..400 {
            c.check_at(&format!("key-{i}"), now);
        }
        assert!(
            c.pending(now).len() <= 25,
            "a tick must not outgrow its own interval"
        );
    }

    #[test]
    fn every_accepted_scheme_reaches_the_same_protocol() {
        // An operator running Recached should not have to write `redis://`.
        for (given, want) in [
            ("recached://cache:6379", "redis://cache:6379"),
            ("recacheds://cache:6379", "rediss://cache:6379"),
            ("valkey://cache:6379", "redis://cache:6379"),
            ("valkeys://cache:6379", "rediss://cache:6379"),
            ("resp://cache:6379", "redis://cache:6379"),
            ("redis://cache:6379", "redis://cache:6379"),
            ("rediss://cache:6379", "rediss://cache:6379"),
        ] {
            assert_eq!(normalize_url(given).as_deref(), Ok(want), "{given}");
        }
    }

    #[test]
    fn an_unusable_url_is_refused_without_echoing_it() {
        // The error reaches a log, and the url very often carries a password.
        let err = normalize_url("https://user:hunter2@cache:6379").unwrap_err();
        assert!(
            !err.contains("hunter2"),
            "password leaked into an error: {err}"
        );
        assert!(
            err.contains("https"),
            "the error should name the scheme: {err}"
        );
        assert!(
            normalize_url("recached://").is_err(),
            "a scheme with no host"
        );
        assert!(normalize_url("cache:6379").is_err(), "no scheme at all");
    }

    #[test]
    fn a_password_never_survives_redaction() {
        for url in [
            "rediss://default:hunter2@cache:6379",
            // A managed host's base64 password contains `/` about half the
            // time, and that is the case a naive split gets wrong.
            "rediss://default:AVNS_xK3/9pQ@cache:25061",
            "rediss://default:pa#ssword@cache:25061",
            "recached://:secret@cache:6379",
            "default:hunter2@cache:6379",
        ] {
            let masked = redact_url(url);
            assert!(masked.contains("***"), "{url} -> {masked}");
            for secret in ["hunter2", "9pQ", "ssword", "secret"] {
                assert!(!masked.contains(secret), "{url} -> {masked}");
            }
        }
    }

    #[test]
    fn redaction_leaves_what_was_never_secret_alone() {
        assert_eq!(redact_url("redis://cache:6379"), "redis://cache:6379");
        assert_eq!(
            redact_url("recached://user@cache:6379"),
            "recached://user@cache:6379",
            "a username with no password is not a credential"
        );
    }

    #[test]
    fn keys_carry_the_configured_prefix() {
        // So one cache can serve this gateway alongside everything else.
        let backend = Arc::new(FakeBackend::default());
        let c = counters(10, backend);
        let now = mid_bucket();
        c.check_at("orders|203.0.113.7", now);
        let batch = c.pending(now);
        assert_eq!(
            batch.first().map(|p| p.key.as_str()),
            Some("t:orders|203.0.113.7")
        );
    }
}
