# Measured policy baseline

Measurements taken October 24, 2026 on Linux 7.2.10-200.fc44.x86_64,
Intel i5-9400F (6 cores, 2.90 GHz), Rust/Cargo 1.98.0. This is a shared developer
machine, not an isolated performance lab. The pinned release/bench profile uses
optimization, thin LTO and one codegen unit. No profiling results are invented.

```sh
CCACHE_DISABLE=1 cargo bench --offline -p lagos-core --no-default-features --bench policy
/usr/bin/time -v target/release/deps/policy-<build-hash>
```

`CCACHE_DISABLE=1` avoids the host C compiler cache's read-only directory in the
workspace sandbox. It changes the build cache, not benchmark behavior. No new
benchmark dependency is required. The fixture JWT uses a reserved `.invalid`
issuer and a public test key; its private signing key was discarded.

`policy-before.csv` records the linear matcher from `e4c9e88` (matcher source
SHA-256 `6b11a0e017efa82012aeb9b56ad53e2a453d034744a729adf8da05e213d93728`).
The benchmark is committed before changing that algorithm. It covers 10, 100,
1,000 and 10,000 routes, mixed hits/misses, table build, header key/plan,
local rate lookup, RS256 decode/verification, single/pool upstream selection and
literal-address DNS warm lookup. The corresponding whole-run CPU/RSS data is
in `policy-before-resources.txt`; builds are excluded from those measurements.

For request operations, each of 200 samples is a batch of 32 operations (128
for very short helpers), after 32 warmups. Table builds use 30 samples of one
operation, after 32 warmups. Percentiles describe **batch mean nanoseconds per
operation**, not individual HTTP request latencies. Build includes cloning
resolved route fixtures. Match paths cycle deterministically across routes;
one third of routes restrict the host. The DNS fixture uses a literal loopback
address and does not measure external DNS or a cold resolver.

This baseline establishes a route-count scaling problem. Header-plan and
signature results are separate costs, not a complete proxy-request benchmark.
No whole-gateway RPS, HTTP p99, allocation count, concurrent streaming or cache
throughput claim follows from these microbenchmarks. Those workloads require
a local load run with an origin and the same gateway build/configuration.

The manual `Policy benchmarks` workflow records environment and CSV artifacts;
it does not gate ordinary contributor PRs on noisy performance thresholds.

## Segment index (C2)

`policy-after.csv` and `policy-after-resources.txt` were taken with the same
command, machine and toolchain after adding `routes/index.rs`. Tables above 32
routes use an arena-backed segment trie; smaller tables keep the linear scan,
which the baseline showed is already cheap and contiguous. p50 batch ns/op:

| Workload | Routes | Linear | Indexed |
| --- | ---: | ---: | ---: |
| mixed hit | 10 | 67.03 | 68.97 (linear path; noise) |
| mixed hit | 100 | 223.38 | 146.25 |
| mixed hit | 1,000 | 2,139.19 | 195.78 |
| mixed hit | 10,000 | 35,512.84 | 460.59 |
| miss | 100 | 328.88 | 77.31 |
| miss | 1,000 | 4,592.66 | 76.78 |
| miss | 10,000 | 70,278.91 | 77.53 |
| table build | 100 | 48,327 | 69,831 |
| table build | 1,000 | 561,858 | 747,959 |
| table build | 10,000 | 9,432,745 | 12,236,142 |

Lookup cost now follows the number of configured path segments a request
shares with the table rather than the route count. The price is roughly 30%
more build time (about 2.8 ms more at 10,000 routes), paid once per startup or
reload, off the request path. Other workloads moved within run-to-run noise.

Equivalence: `indexed_matching_equals_reference_across_generated_routes_and_listeners`
compares the index with the original linear predicate over generated route
sets (host-specific, wildcard and host-less routes; method filters; disabled
routes; repeated and non-ASCII segments; both listener partitions; a 2,000
segment path). `prefix_candidates` (CLI explain / why-not) still scans
linearly, so its diagnostics are unchanged.

## Cache storage (C4)

`cargo bench -p lagos-core --bench cache` drives `MemoryStorage` directly
through Pingora's `Storage` interface: hits (lookup plus reading the whole
body), fills (miss handler, one body write, finish), fills into a cache that
holds about 16 bodies so nearly every fill evicts, missing-key lookups, and
hits from every core at once (aggregate ns per hit). Same machine, toolchain
and method as above; 1,024 keys cycle; 200 samples for hits, 60 for fills, each
of 256 operations. It does not include HTTP parsing, `pingora-cache` freshness
logic or the cache lock, so it bounds storage cost only.

`cache-before.csv` is the storage before the in-flight fill budget; three
runs each, p50 ns/op:

| Workload | Body | Before | After budget |
| --- | ---: | ---: | ---: |
| hit | 1 KiB | 1,467–1,693 | 1,470–1,681 |
| hit | 1 MiB | 2,314–2,427 | 2,304–2,323 |
| fill | 1 KiB | 3,994–4,234 | 4,139–4,199 |
| fill | 1 MiB | 89,127–92,502 | 88,049–89,293 |
| fill, evicting | 1 MiB | 104,548–117,867 | 115,881–117,472 |
| miss lookup | – | 595–597 | 578–579 |
| hit, 6 threads (aggregate) | 1 KiB | 412–434 | 414–552 |

The budget is one atomic update per body chunk; its cost is inside run-to-run
noise. Hits are dominated by fixed per-lookup work rather than body size (a
1 MiB hit costs about 1.5x a 1 KiB one, since bodies are shared slices).
Peak RSS in `cache-*-resources.txt` (about 2.4 GB) is the benchmark's own warm
sets of 1,024 bodies up to 1 MiB, not gateway overhead.

### Binary cache keys

The storage used the hex `CacheKey::combined()` string as its map key, which
formats and allocates on every lookup. It now uses the 16-byte
`combined_bin()` hash (same hash, so the same collision properties). Three
runs, p50 ns/op, `cache-binary-key.csv`:

| Workload | Body | String key (after budget) | Binary key |
| --- | ---: | ---: | ---: |
| miss lookup | – | 578–579 | 255–256 |
| hit | 1 KiB | 1,470–1,681 | 1,099–1,351 |
| hit | 64 KiB | 1,509–1,522 | 1,146–1,186 |
| hit | 1 MiB | 2,304–2,323 | 1,941–1,993 |
| fill | 1 KiB | 4,139–4,199 | 3,687–3,897 |
| fill, evicting | 1 MiB | 115,881–117,472 | 99,758–104,106 |
| hit, 6 threads (aggregate) | 1 KiB | 414–552 | 368–477 |

`cache_meta_deserialize` (about 715 ns) is now the largest fixed cost of a
hit. `CacheMeta` is not `Clone` in pingora-cache 0.9, so every lookup must
rebuild it from the stored halves; rebuilding it through `CacheMeta::new`
would drop internal fields, so that cost is left alone.

## Whole-gateway HTTP load (C5)

`benches/http/run.sh [requests] [concurrency]` starts the release gateway
(`benches/http/gateway.yml`, default 2 worker threads), a bun origin and a
JWKS fixture, and drives four routes with ApacheBench keep-alive: proxied,
cache hit, JWT-authenticated proxy, and an unrouted 404. Everything shares the
6-core host, so the numbers compare workloads; they are not a capacity
figure. ab reports whole-millisecond percentiles only. `http-baseline.csv`
(100,000 requests, concurrency 32):

| Workload | req/s | p50 / p99 ms | Gateway CPU |
| --- | ---: | --- | ---: |
| proxy | 27,215 | 1 / 2 | 172% |
| cache hit | 40,731 | 1 / 1 | 177% |
| JWT proxy | 17,535 | 2 / 3 | 182% |
| 404 refusal | 63,358 | 0 / 1 | 170% |

The gateway saturates its two workers in every case. Flat `perf` profiles
(symbols via `CARGO_PROFILE_RELEASE_STRIP=false
CARGO_PROFILE_RELEASE_DEBUG=line-tables-only PERF=1`) grouped by component:

| Workload | Largest shares of gateway CPU |
| --- | --- |
| proxy | Pingora 24%, allocator 22%, Lagos 15%, http/bytes 10%, tokio 7%, mem* 6%, logging 5% |
| cache hit | allocator 19%, Pingora 19%, Lagos 13%, http/bytes 8%, logging 7% |
| JWT proxy | RSA verification (ring) 27%, allocator 17%, Pingora 14%, Lagos 10% |
| 404 refusal | logging 17%, Pingora 16%, allocator 14%, Lagos 13% |

No single Lagos function exceeds 2.5%, so no Lagos-side refactor is justified
by this profile. Call-graph profiles could not be taken on this host
(`perf_event_paranoid=2` and the per-user perf mlock budget refused them under
load), so allocator time is not attributed to callers.

### Measured but not adopted: jemalloc

A throwaway build with `tikv-jemallocator` 0.6 as the global allocator, three
alternating rounds of 60,000 requests each against the same origin and token:

| Workload | glibc req/s | jemalloc req/s | Median |
| --- | --- | --- | ---: |
| proxy | 27,256–28,349 | 30,763–32,229 | +12.3% |
| cache hit | 40,432–42,374 | 44,220–45,591 | +9.5% |
| JWT proxy | 16,856–17,683 | 19,895–20,706 | +15.2% |
| 404 refusal | 62,540–63,827 | 65,790–66,805 | +5.2% |
| peak RSS | 22.4–23.1 MiB | 20.7–21.6 MiB | −6.1% |

The ranges do not overlap. It is not adopted here because it adds a C
dependency to the static musl and multi-architecture release builds, which
need their own verification; it is the largest measured lever available.

### Not attempted: verified-token caching

RS256 verification is 27% of CPU on authenticated traffic. Caching successful
verifications by token hash would remove most of it, but it is a security
design (expiry, key rotation and revocation, memory bounds) rather than an
optimization, and is left for a dedicated change.
