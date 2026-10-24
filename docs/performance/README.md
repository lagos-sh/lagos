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
