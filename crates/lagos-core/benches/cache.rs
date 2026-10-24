//! Reproducible, dependency-free microbenchmarks for the response-cache
//! storage. Samples are batch means, not HTTP latency distributions. Run with
//! `cargo bench --bench cache` (needs the default `cache` feature).
// Constant local benchmark fixtures only; indices are always `% KEYS`.
#![allow(clippy::expect_used, clippy::indexing_slicing)]

use std::hint::black_box;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use lagos_core::cache::storage::MemoryStorage;
use pingora::cache::storage::Storage;
use pingora::cache::trace::Span;
use pingora::cache::{CacheKey, CacheMeta};
use pingora::http::ResponseHeader;

/// Each sample runs `ops` operations through `batch`; reports ns per operation.
fn measure(name: &str, size: usize, samples: usize, ops: usize, mut batch: impl FnMut()) {
    for _ in 0..4 {
        batch();
    }
    let mut times = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        batch();
        times.push(start.elapsed().as_secs_f64() * 1e9 / ops as f64);
    }
    times.sort_by(f64::total_cmp);
    let percentile = |percent| {
        times
            .get((samples.saturating_sub(1) * percent) / 100)
            .copied()
            .unwrap_or_default()
    };
    let mean = times.iter().sum::<f64>() / samples as f64;
    println!(
        "{name},{size},{:.2},{:.2},{:.2},{mean:.2}",
        percentile(50),
        percentile(95),
        percentile(99)
    );
}

fn meta() -> CacheMeta {
    let mut header = ResponseHeader::build(200, None).expect("status");
    header
        .insert_header("content-type", "application/json")
        .expect("header");
    header
        .insert_header("cache-control", "public, max-age=60")
        .expect("header");
    let now = SystemTime::now();
    CacheMeta::new(now + Duration::from_secs(60), now, 0, 0, header)
}

fn key(i: usize) -> CacheKey {
    CacheKey::new(format!("route\0upstream\0host\0GET\0/items/{i}"), "")
}

fn storage(max_bytes: u64) -> &'static MemoryStorage {
    Box::leak(Box::new(MemoryStorage::new(max_bytes, 8 * 1024 * 1024)))
}

async fn fill(s: &'static MemoryStorage, key: &CacheKey, meta: &CacheMeta, body: &Bytes) {
    let span = Span::inactive().handle();
    let mut miss = s
        .get_miss_handler(key, meta, &span)
        .await
        .expect("miss handler");
    miss.write_body(body.clone(), true).await.expect("write");
    miss.finish().await.expect("finish");
}

async fn hit(s: &'static MemoryStorage, key: &CacheKey) -> usize {
    let span = Span::inactive().handle();
    let (_, mut handler) = s
        .lookup(key, &span)
        .await
        .expect("lookup")
        .expect("present");
    let mut read = 0;
    while let Some(chunk) = handler.read_body().await.expect("read") {
        read += chunk.len();
    }
    read
}

fn main() {
    println!(
        "workload,body_bytes,p50_batch_ns_per_op,p95_batch_ns_per_op,p99_batch_ns_per_op,mean_ns_per_op"
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    let meta = meta();
    const KEYS: usize = 1024;
    const OPS: usize = 256;
    let keys: Vec<CacheKey> = (0..KEYS).map(key).collect();

    for size in [1024usize, 64 * 1024, 1024 * 1024] {
        let body = Bytes::from(vec![7u8; size]);
        let warm = storage(4 * 1024 * 1024 * 1024);
        rt.block_on(async {
            for k in &keys {
                fill(warm, k, &meta, &body).await;
            }
        });

        let mut next = 0;
        measure("cache_hit", size, 200, OPS, || {
            rt.block_on(async {
                for _ in 0..OPS {
                    next = (next + 1) % KEYS;
                    black_box(hit(warm, &keys[next]).await);
                }
            })
        });

        // Distinct keys into a cache large enough to hold them all.
        let roomy = storage(4 * 1024 * 1024 * 1024);
        let mut next = 0;
        measure("cache_fill", size, 60, OPS, || {
            rt.block_on(async {
                for _ in 0..OPS {
                    next = (next + 1) % KEYS;
                    fill(roomy, &keys[next], &meta, &body).await;
                }
            })
        });

        // A cache holding about 16 bodies, so nearly every fill evicts.
        let tight = storage((16 * size) as u64);
        let mut next = 0;
        measure("cache_fill_evicting", size, 60, OPS, || {
            rt.block_on(async {
                for _ in 0..OPS {
                    next = (next + 1) % KEYS;
                    fill(tight, &keys[next], &meta, &body).await;
                }
            })
        });
    }

    let empty = storage(1024 * 1024);
    let span = Span::inactive().handle();
    let mut next = 0;
    measure("cache_miss_lookup", 0, 200, OPS, || {
        rt.block_on(async {
            for _ in 0..OPS {
                next = (next + 1) % KEYS;
                black_box(empty.lookup(&keys[next], &span).await.expect("lookup"));
            }
        })
    });

    // What a hit must pay before touching the body: `CacheMeta` is not
    // `Clone`, so every lookup rebuilds it from the stored halves.
    let (internal, header) = meta.serialize().expect("serialize");
    measure("cache_meta_deserialize", 0, 200, OPS, || {
        for _ in 0..OPS {
            black_box(CacheMeta::deserialize(&internal, &header).expect("deserialize"));
        }
    });

    // Concurrent readers on one shared storage: aggregate ns per hit across
    // all threads, so lower means more total throughput.
    let body = Bytes::from(vec![7u8; 1024]);
    let shared = storage(64 * 1024 * 1024);
    rt.block_on(async {
        for k in &keys {
            fill(shared, k, &meta, &body).await;
        }
    });
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    measure(
        &format!("cache_hit_concurrent_{threads}t"),
        1024,
        60,
        OPS * threads,
        || {
            std::thread::scope(|scope| {
                for t in 0..threads {
                    let keys = &keys;
                    scope.spawn(move || {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .build()
                            .expect("runtime");
                        rt.block_on(async {
                            for i in 0..OPS {
                                black_box(hit(shared, &keys[(t * 131 + i) % KEYS]).await);
                            }
                        });
                    });
                }
            });
        },
    );
}
