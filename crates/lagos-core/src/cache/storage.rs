//! Bounded in-memory cache storage.
//!
//! `pingora-cache` supplies the HTTP semantics — freshness, revalidation,
//! `Vary`, range handling, the cache lock that stops a stampede — but the only
//! [`Storage`] it ships is `MemCache`, whose own documentation says *"For
//! testing only, not for production use"*: an unbounded `HashMap`. In a gateway
//! that is a memory-exhaustion bug, so the backend is ours.
//!
//! # What this stores, and what it refuses to
//!
//! **Complete objects only.** [`Storage::support_streaming_partial_write`] stays
//! `false`, so a reader is never handed a partially filled entry. The body is
//! accumulated by the miss handler and published in one step when the fill
//! finishes; a handler dropped without finishing stores nothing. That makes a
//! torn read structurally impossible rather than a thing to get right, and the
//! cost — a second request for the same key waits rather than streaming along
//! behind the first — is what `pingora-cache`'s lock is for anyway.
//!
//! # Two bounds, because one is not enough
//!
//! `max_size` caps the **total bytes** held. Capping entry *count* instead
//! would make the footprint depend on what the upstreams happen to return:
//! ten 100 MB objects and ten thousand 10 KB ones are not the same cache.
//!
//! `max_object_size` caps a **single** object, and is enforced *as the body
//! streams in*, not after. Without it a 10 GB response would be accumulated in
//! full before anything noticed it did not fit — the cache would stay within
//! its bound and the process would still die. Over the cap, the fill is
//! abandoned and the response is proxied through uncached.

use std::any::Any;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use pingora::Result;
use pingora::cache::CacheMeta;
use pingora::cache::key::{CacheHashKey, CacheKey};
use pingora::cache::storage::{
    HandleHit, HandleMiss, HitHandler, MissFinishType, MissHandler, PurgeOutcome, PurgeTarget,
    PurgeType, Storage,
};
use pingora::cache::trace::SpanHandle;

/// One stored response. Immutable once published, so readers share it.
struct Entry {
    /// `CacheMeta`'s two serialized halves.
    internal: Vec<u8>,
    header: Vec<u8>,
    body: Bytes,
}

impl Entry {
    /// What this entry costs the cache. The metadata is counted too — a cache
    /// of many tiny bodies is mostly headers.
    fn weight(&self) -> u32 {
        let total = self
            .body
            .len()
            .saturating_add(self.internal.len())
            .saturating_add(self.header.len());
        u32::try_from(total).unwrap_or(u32::MAX)
    }
}

pub struct MemoryStorage {
    entries: moka::sync::Cache<String, Arc<Entry>>,
    max_object_bytes: usize,
}

impl MemoryStorage {
    pub fn new(max_bytes: u64, max_object_bytes: usize) -> Self {
        Self {
            entries: moka::sync::Cache::builder()
                // Weighted by bytes, so eviction happens on the bound that
                // actually matters.
                .weigher(|_k: &String, v: &Arc<Entry>| v.weight())
                .max_capacity(max_bytes)
                .build(),
            max_object_bytes,
        }
    }

    /// Bytes currently held. Approximate: moka applies evictions lazily.
    pub fn weighted_size(&self) -> u64 {
        self.entries.run_pending_tasks();
        self.entries.weighted_size()
    }

    pub fn entry_count(&self) -> u64 {
        self.entries.run_pending_tasks();
        self.entries.entry_count()
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn lookup(
        &'static self,
        key: &CacheKey,
        _trace: &SpanHandle,
    ) -> Result<Option<(CacheMeta, HitHandler)>> {
        let Some(entry) = self.entries.get(&key.combined()) else {
            return Ok(None);
        };
        let meta = CacheMeta::deserialize(&entry.internal, &entry.header)?;
        Ok(Some((
            meta,
            Box::new(Hit {
                body: entry.body.clone(),
                read: 0,
                end: entry.body.len(),
            }),
        )))
    }

    async fn get_miss_handler(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> Result<MissHandler> {
        let (internal, header) = meta.serialize()?;
        Ok(Box::new(Miss {
            storage: self,
            key: key.combined(),
            internal,
            header,
            body: BytesMut::new(),
            too_large: false,
        }))
    }

    async fn purge(
        &'static self,
        target: PurgeTarget<'_>,
        _purge_type: PurgeType,
        _trace: &SpanHandle,
    ) -> Result<PurgeOutcome> {
        let hash = target.key().combined();
        if self.entries.remove(&hash).is_some() {
            // This storage keeps one generation per key and no entry identity,
            // so there is nothing for the eviction manager to reconcile.
            Ok(PurgeOutcome::Purged(None))
        } else {
            Ok(PurgeOutcome::NotFound)
        }
    }

    async fn update_meta(
        &'static self,
        key: &CacheKey,
        meta: &CacheMeta,
        _trace: &SpanHandle,
    ) -> Result<bool> {
        let hash = key.combined();
        let Some(existing) = self.entries.get(&hash) else {
            return Ok(false);
        };
        let (internal, header) = meta.serialize()?;
        // Replace rather than mutate: readers hold an `Arc` to the old entry
        // and must keep seeing a consistent meta/body pair for as long as they
        // are reading it.
        self.entries.insert(
            hash,
            Arc::new(Entry {
                internal,
                header,
                body: existing.body.clone(),
            }),
        );
        Ok(true)
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync + 'static) {
        self
    }
}

/// A reader over one complete, immutable body.
struct Hit {
    body: Bytes,
    read: usize,
    end: usize,
}

/// How much body to hand back at a time.
///
/// The body is already in memory, so this is about not handing a multi-megabyte
/// `Bytes` to the downstream writer in one piece and stalling the task.
const READ_CHUNK: usize = 32 * 1024;

#[async_trait]
impl HandleHit for Hit {
    async fn read_body(&mut self) -> Result<Option<Bytes>> {
        if self.read >= self.end {
            return Ok(None);
        }
        let stop = self.end.min(self.read.saturating_add(READ_CHUNK));
        let chunk = self.body.slice(self.read..stop);
        self.read = stop;
        Ok(Some(chunk))
    }

    async fn finish(
        self: Box<Self>,
        _storage: &'static (dyn Storage + Sync),
        _key: &CacheKey,
        _trace: &SpanHandle,
    ) -> Result<()> {
        Ok(())
    }

    /// The body is one contiguous buffer, so a range request can be served from
    /// the cache instead of going to the upstream for bytes we already hold.
    fn can_seek(&self) -> bool {
        true
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync + 'static) {
        self
    }

    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync + 'static) {
        self
    }

    fn seek(&mut self, start: usize, end: Option<usize>) -> Result<()> {
        let len = self.body.len();
        // Clamped rather than rejected: `pingora-cache` has already validated
        // the range against the stored length, and panicking on a slice here
        // would turn a malformed range into a dead worker.
        self.read = start.min(len);
        self.end = end.unwrap_or(len).min(len).max(self.read);
        Ok(())
    }
}

/// Accumulates a body, and publishes it only if the whole thing arrives and
/// fits.
struct Miss {
    storage: &'static MemoryStorage,
    key: String,
    internal: Vec<u8>,
    header: Vec<u8>,
    body: BytesMut,
    /// Set once the object has outgrown `max_object_size`. The buffer is
    /// released at that point and nothing is stored.
    too_large: bool,
}

#[async_trait]
impl HandleMiss for Miss {
    async fn write_body(&mut self, data: Bytes, _eof: bool) -> Result<()> {
        if self.too_large {
            return Ok(());
        }
        if self.body.len().saturating_add(data.len()) > self.storage.max_object_bytes {
            // Stop accumulating *now*. Buffering the rest only to discard it
            // would let one oversized response take the process out while the
            // cache stayed politely within its own bound.
            self.too_large = true;
            self.body = BytesMut::new();
            return Ok(());
        }
        self.body.extend_from_slice(&data);
        Ok(())
    }

    async fn finish(self: Box<Self>) -> Result<MissFinishType> {
        if self.too_large {
            // Nothing stored; the response was already streamed downstream.
            return Ok(MissFinishType::Created(0));
        }
        let size = self.body.len();
        self.storage.entries.insert(
            self.key,
            Arc::new(Entry {
                internal: self.internal,
                header: self.header,
                body: self.body.freeze(),
            }),
        );
        Ok(MissFinishType::Created(size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage(max_bytes: u64, max_object: usize) -> &'static MemoryStorage {
        Box::leak(Box::new(MemoryStorage::new(max_bytes, max_object)))
    }

    /// Drive a miss handler the way the proxy does: write, then finish.
    async fn store(s: &'static MemoryStorage, key: &str, body: &[u8]) {
        let mut miss = Miss {
            storage: s,
            key: key.to_string(),
            internal: Vec::new(),
            header: Vec::new(),
            body: BytesMut::new(),
            too_large: false,
        };
        miss.write_body(Bytes::copy_from_slice(body), true)
            .await
            .unwrap();
        Box::new(miss).finish().await.unwrap();
    }

    #[tokio::test]
    async fn an_object_over_the_per_object_cap_is_not_stored() {
        // And, more importantly, is not buffered on the way to being rejected.
        let s = storage(1 << 20, 100);
        let mut miss = Miss {
            storage: s,
            key: "k".into(),
            internal: Vec::new(),
            header: Vec::new(),
            body: BytesMut::new(),
            too_large: false,
        };
        for _ in 0..50 {
            miss.write_body(Bytes::from(vec![0u8; 64]), false)
                .await
                .unwrap();
            assert!(
                miss.body.len() <= 100,
                "the buffer kept growing past the cap: {}",
                miss.body.len()
            );
        }
        assert!(miss.too_large);
        Box::new(miss).finish().await.unwrap();
        assert_eq!(s.entry_count(), 0, "nothing should have been stored");
    }

    #[tokio::test]
    async fn the_store_is_bounded_by_bytes_not_entries() {
        let s = storage(4096, 4096);
        for i in 0..200 {
            store(s, &format!("k{i}"), &vec![0u8; 512]).await;
        }
        assert!(
            s.weighted_size() <= 4096 + 512,
            "held {} bytes against a 4096 bound",
            s.weighted_size()
        );
    }

    #[tokio::test]
    async fn a_dropped_write_stores_nothing() {
        // `finish` is the commit point; a handler that goes away mid-fill must
        // not leave a truncated entry behind to be served as complete.
        let s = storage(1 << 20, 1 << 20);
        let mut miss = Miss {
            storage: s,
            key: "k".into(),
            internal: Vec::new(),
            header: Vec::new(),
            body: BytesMut::new(),
            too_large: false,
        };
        miss.write_body(Bytes::from_static(b"half"), false)
            .await
            .unwrap();
        drop(miss);
        assert_eq!(s.entry_count(), 0);
    }

    #[tokio::test]
    async fn a_hit_reads_the_whole_body_in_chunks() {
        let body = vec![7u8; READ_CHUNK * 2 + 13];
        let mut hit = Hit {
            body: Bytes::from(body.clone()),
            read: 0,
            end: body.len(),
        };
        let mut out = Vec::new();
        while let Some(chunk) = hit.read_body().await.unwrap() {
            out.extend_from_slice(&chunk);
        }
        assert_eq!(out, body, "the reassembled body must match byte for byte");
        assert!(hit.read_body().await.unwrap().is_none(), "and then stop");
    }

    #[tokio::test]
    async fn seeking_serves_a_range_from_the_stored_body() {
        let mut hit = Hit {
            body: Bytes::from_static(b"0123456789"),
            read: 0,
            end: 10,
        };
        hit.seek(2, Some(5)).unwrap();
        let chunk = hit.read_body().await.unwrap().unwrap();
        assert_eq!(&chunk[..], b"234");
    }

    #[tokio::test]
    async fn an_out_of_range_seek_is_clamped_rather_than_panicking() {
        // Slicing past the end would kill the worker thread; a malformed range
        // must not be able to do that.
        let mut hit = Hit {
            body: Bytes::from_static(b"abc"),
            read: 0,
            end: 3,
        };
        hit.seek(99, Some(1000)).unwrap();
        assert!(hit.read_body().await.unwrap().is_none());
    }
}
