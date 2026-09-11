//! HTTP response caching.
//!
//! The semantics are `pingora-cache`'s; [`storage`] is ours, because the only
//! backend that crate ships is documented as test-only and is unbounded.

pub mod storage;

pub use storage::MemoryStorage;

use std::time::Duration;

use pingora::cache::CacheMetaDefaults;
use pingora::cache::eviction::simple_lru::Manager as LruManager;
use pingora::cache::lock::{CacheKeyLockImpl, CacheLock};

use crate::config::CacheConfig;

/// Freshness for responses whose upstream said nothing about caching.
///
/// Set once when the cache is built; see [`Cache::new`].
static DEFAULT_TTL: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();

/// How long an uninstructed response stays fresh, by status.
///
/// Only success and permanent redirects are cacheable by default. Caching an
/// error for a minute turns a momentary blip into an outage that outlives its
/// own cause, and a 404 held past a resource being created is a bug report
/// nobody can reproduce.
fn default_freshness(status: http::StatusCode) -> Option<Duration> {
    match status.as_u16() {
        200..=299 | 301 | 308 => Some(*DEFAULT_TTL.get().unwrap_or(&Duration::from_secs(60))),
        _ => None,
    }
}

/// Everything the proxy needs to serve a route from cache.
///
/// All four pieces have to outlive every request, and `pingora-cache` demands
/// `&'static` for the storage and the eviction manager, so this is built once
/// at startup and leaked. There is exactly one per process and it is never
/// rebuilt, which is also why a configuration reload cannot resize the cache.
pub struct Cache {
    pub storage: &'static MemoryStorage,
    pub eviction: &'static LruManager,
    pub lock: &'static CacheKeyLockImpl,
    pub defaults: CacheMetaDefaults,
}

impl Cache {
    pub fn new(cfg: &CacheConfig) -> Self {
        let max_object = usize::try_from(cfg.max_object_size).unwrap_or(usize::MAX);
        let storage = Box::leak(Box::new(MemoryStorage::new(cfg.max_size, max_object)));

        // The eviction manager decides *which* keys to drop; the storage is
        // separately bounded by bytes. Both are needed: the manager keeps the
        // accounting `pingora-cache` uses for admission, the storage is what
        // actually holds — and releases — memory.
        let eviction = Box::leak(Box::new(LruManager::new(
            usize::try_from(cfg.max_size).unwrap_or(usize::MAX),
        )));

        // Without this, every concurrent miss on the same key becomes its own
        // upstream request — a cache that stampedes the origin it exists to
        // protect. The timeout bounds how long a waiter blocks if the filling
        // request stalls.
        let lock: &'static CacheKeyLockImpl =
            Box::leak(CacheLock::new_boxed(Duration::from_secs(2)));

        // `FreshDurationByStatusFn` is a plain fn pointer, so the configured
        // TTL cannot be captured in a closure. There is one cache per process
        // and it is built once, so a set-once global is the honest way to get
        // it to the function.
        let _ = DEFAULT_TTL.set(cfg.default_ttl);
        let swr = u32::try_from(cfg.stale_while_revalidate.as_secs()).unwrap_or(u32::MAX);

        Self {
            storage,
            eviction,
            lock,
            defaults: CacheMetaDefaults::new(
                default_freshness,
                swr,
                // stale-if-error is deliberately 0: serving a stale body
                // because the upstream is failing is a policy decision an
                // operator should make per deployment, not a default.
                0,
            ),
        }
    }
}
