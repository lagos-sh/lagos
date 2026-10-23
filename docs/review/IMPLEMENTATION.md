# Production improvement checklist

Reviewed starting point: `9925ed5` (clean worktree), workspace 0.1.8,
locked Pingora 0.9.0, Rust 1.98.0. Source review is not a deployed pentest.
No deployment, publication or repository-setting changes are authorized.

Initial implementation order: fail-closed admission keys; shared cache isolation;
JWT/JWKS correctness; reload validation/state; extension budgets; benchmark
baseline; measured optimizations; CI/release and documentation. Keep patches
independent and record checks honestly.

| Task | Initial verified state | Effort / compatibility | Status |
| --- | --- | --- | --- |
| 1. Required limiter keys | `proxy.rs:568` returns unlimited on missing key; concurrency at 1394 also skips. Header reads only first field. | Medium; missing/ambiguous keys will reject by default. | In progress |
| 2. Shared cache | `cache/policy.rs:39` allows Set-Cookie; Pingora 0.9 explicitly tests retaining it (`filters.rs:640`). Arbitrary application cookies can select shared anonymous entries. | Small; less caching for cookie traffic. | Pending |
| 3. Cookie CSRF | README/SECURITY already assign protection to application. CORS is not CSRF. | Medium if gateway policy added; opt-in only. | Pending review/documentation |
| 4. Resource controls | Header deadline, body cap, per-I/O limits and per-address accept rate exist. Pingora HTTP/1 parser already bounds 256 fields/~1 MiB, not operator configurable. Total request deadline/global live cap absent. | Large; streaming lifetime semantics need care. | Pending |
| 5. Security regressions | Recursive decoding, case-folded deny rules, spoofed identity removal, listener isolation and JWT checks already tested. Firebase `iat` missing explicit validation. Duplicate Authorization needs integration reproduction. | Medium. | Pending |
| 6. JWKS resilience | Expired/cold failures closed; refresh coalescing exists. Cancelled refresh leader strands broadcast sender (`auth/jwks.rs:132–172`). No bounded stale mode. | Medium; stale mode has revocation tradeoff. | Pending |
| 7. Extensions | Missing hooks fail closed at runtime, but no hook/chain budget or admission limit. Native code trusted. | Medium; finite defaults can reject slow hooks. | Pending |
| 8. Reload state | Atomic validated snapshots, generation cache invalidation and persistent concurrency already exist. Local quotas reset. Registry validation omitted at reload (`runtime.rs:427`). | Medium; reuse only compatible policy. | Pending |
| 9. Replicas | Optional exact/approximate shared counters implemented, capability checked; concurrency/breakers local. | Small documentation; no mandatory store. | Pending |
| 10. Baselines | No committed repeatable route benchmark. | Medium; report measured values only. | Pending |
| 11. Matcher | Linear scan preserves host precedence then longest prefix and boundaries. | Benchmark first; no speculative trie. | Pending |
| 12. Allocation | Matcher allocates normalized method/host. No profiling yet. | Benchmark first. | Pending |
| 13. DNS | Bounded TTL DNS cache and coordinated misses; static pool discovery pins initial addresses. | Large; atomic health-aware replacement. | Pending |
| 14. Cache performance | Complete immutable entries, per-object cap, eviction and fill lock exist. Aggregate concurrent fill memory needs measurement. | Medium. | Pending |
| 15. Architecture | One request authorization boundary, response/cache policy separated already. | Refactor only after fixes/measurement. | Pending |
| 16. Error handling | Unsafe forbidden, strict request panic lints, bounded metric labels. | Medium review. | Pending |
| 17. CI | fmt/Clippy/test/lean/E2E/deny already run. Toolchain action uses moving stable despite pin. | Small. | Pending |
| 18. Branch protection | Remote administration not yet inspected. No settings changes authorized. | Read-only/manual instructions. | Pending |
| 19. Release integrity | Digest-based platform publish, native checksums, locked builds exist. Provenance disabled. | Medium; preserve publication architecture. | Pending |
| 20. Docs/versions | Published starter tags intentionally differ from workspace version; preserve. SECURITY has obsolete shared-limit gap. | Small. | Pending |

Existing cache defenses: authorization/bindings before lookup; length-framed
route/upstream/host/method/URI/generation keys; hit eligibility rechecks; Vary
uses effective forwarded identity; wildcard/malformed Vary rejected. Keep them.

Validation environment: cached dependencies and pinned toolchain are installed.
An attempted isolated network namespace (`bwrap --unshare-net ... true`) failed
with `Failed to create NETLINK_ROUTE socket: Operation not permitted`. Execute
requested repository checks within the workspace sandbox, offline where
possible; do not claim this is the full independent exploit-sandbox workflow.
No Strix executable is installed; no cloud upload or paid scan was attempted.

Detailed changes and command results will be appended here before handoff.

## A1 — admission keys

Implemented explicit `missing_key` policy for rate limits/concurrency, strict
single opaque header keys, normalized OWS, CLI explain/effective/diff, offline
key assertions and generated schemas. Missing keys default to 400; route/IP
fallback and explicit optional skip remain available. Route-fallback concurrency
uses exact route accounting. Independent source review caught and corrected
schema/CLI/offline identity mismatches.

Checks: `cargo test --offline -p lagos-core ratelimit --lib` (51 passed),
`cargo test --offline -p lagos --test explain --test schema` (9 passed),
`cargo clippy --offline --workspace --all-targets -- -D warnings` passed.
Local regression suite passed 54 gateway and 18 route-default checks before
adding the held fallback concurrency case (included in final rerun).
Default sandbox cannot create sockets; loopback regression run was approved
through tool escalation and passed. No external service was contacted.

## A2 — shared cache

Cookie-setting responses are rejected at both fills and hits. Every Cookie
request bypasses lookup/fill regardless of configured authentication cookie
names, Vary or public directives. Existing authenticated public sharing and
verified-identity variants remain covered. `cargo test --offline -p lagos-core
cache:: --lib`: 14 passed. The broader `cache` substring filter also selected
three JWKS socket tests that failed under sandbox socket restrictions (not code
failures); final workspace tests require loopback permission. Updated local
E2E: 68 gateway regression checks passed, including held fallback concurrency
and anonymous/session-cookie isolation. Final full suite follows later patches.

## A3 — Firebase timestamps

Explicit post-signature checks now require unsigned `iat` and `auth_time` and
reject future values outside clock skew. This follows Firebase's published
[verification requirements](https://firebase.google.com/docs/auth/admin/verify-id-tokens).
Six focused unit tests passed; twelve signed-token variants were added to the
full E2E suite for final execution. No change to signature/audience/expiry rules.
