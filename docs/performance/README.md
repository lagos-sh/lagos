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
