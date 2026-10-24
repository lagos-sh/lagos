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

## B1 — JWKS cancellation and stale keys

Implemented cancellation-safe leadership and issuer-specific opt-in
`stale_if_error` (zero default). Fixed deadline is original expiry plus grace;
only a cached matching kid can be returned. Normal signature/claim checks still
run. Successful rotation replaces keys; removed keys cannot be resurrected.
Metrics distinguish refresh failure, stale use and exhausted grace. Existing
constructors keep default behavior; builders opt in. Schemas regenerated.

Independent review identified an old-leader/new-leader cleanup race, corrected
by disarming under the slot lock before publication. Ten JWKS unit/integration
tests passed with loopback permission, including concurrent failures,
cancellation, rotation, recovery, exhaustion and cold cache. Local E2E passed
73 gateway + 18 defaults checks; wrong-audience, expired, unknown-kid and bad
signature tokens remain rejected during stale-key operation. Initial attempt
against an old binary failed config loading; rebuilt binary passed. Clippy and
schema tests passed before adding the final rotation/outage fixtures; final
workspace checks will cover the complete patch.

## B2 — reload state and validation

Compatible effective limiter policies reuse their synchronized Arc, including
requests in old snapshots. Equality includes every limiter setting and route
identity/scope; changed settings receive a new limiter. Inheritance provenance
alone does not reset state. Cache generations still rotate conservatively.
Startup and reload now share registry validation; a missing extension leaves
the exact prior table and namespace intact. A forced initial validated watcher
load closes the startup-to-watcher mtime race. Same-mtime rewrites remain an
operator/filesystem limitation of polling.

`cargo test --offline -p lagos-core --features shared-limits reload --lib`:
6 passed. Additional unchanged-inheritance test is included in final workspace
execution. E2E now asserts spent quota survives an unrelated reload.

## B3 — cooperative extension budgets

Implemented 2s hook / 5s chain defaults, optional immediate admission cap shared
by registry clones across listeners, and fixed 503 refusal reasons. Partial
plans stay local until success. Permits drop before rejection response I/O and
on cancellation. Duration/outcome histograms identify configured hooks.
Independent review corrected pre-poll chain-expiry handling and unchecked or
conflicting capacity initialization. Native hooks remain trusted/cooperative;
blocking code, detached work and remote side effects are not preempted.

Seven focused extension tests passed (success, rejection, hook/chain timeouts,
capacity sharing and cancellation); configuration validation cases added for
final run. Clippy passed before final narrow capacity/deadline review changes;
final workspace checks cover those changes. Schema, explain/effective output,
upgrade guide and extension proposal now reflect implemented behavior.

Additional reload review found the public store API can receive a new shared
backend even though runtime configuration is frozen. Reuse now also requires
same backend Arc/namespace/batch settings; a focused backend-identity test passed.

## A4 — absolute exchange budget and honest ingress limits

Added optional `timeouts.request_total`, covering dispatched HTTP sessions
through header/auth/hook/upload/stream completion. Expiry closes the exchange,
with a dedicated metric, rather than misclassifying it as an upstream timeout
or claiming an impossible replacement status after streaming starts. Existing
constructor/default SSE behavior remains compatible. Parser-level custom
header bytes and global live-connection limits remain explicit ingress duties;
Pingora's existing approximate 1 MiB/256-field parser protection is documented.

Three downstream unit tests and five local E2E checks passed: stalled upstream,
progressing stream, incomplete header, concurrency release and metric. Full
suite also now makes its intentionally optional anonymous identity quota use
explicit `missing_key: skip` rather than depending on the old implicit bypass.

## A5 — opt-in browser-cookie origin policy

Implemented exact trusted Origin tuples for unsafe gateway-cookie requests,
with separately opt-in Referer fallback only when Origin is absent. Null,
missing, malformed, duplicate and untrusted fields fail closed. Bearer clients
and safe methods retain JWT verification. Config validation rejects wildcards,
non-HTTP origins, paths and userinfo; a regression caught URL parser wildcard
permissiveness and the explicit rejection now passes. Duplicate Authorization
fields reject on verifying routes instead of selecting one credential.

Two focused CSRF tests passed and Clippy passed. Local E2E exercised safe cookie
requests, unsafe positive/negative Origin/Referer cases, duplicate Origin,
bearer compatibility and repeated credentials. Application CSRF responsibilities,
SameSite/deployment choices and default-disabled migration are documented.

A5 integration follow-up: complete local suite now passes 83 gateway and 19
route-default checks. Corrected two fixture assumptions: configured credential
stripping removes empty Cookie fields; and an old reload log plus 404 cannot
prove a new route is active. The test now waits for that new route's admitted
request and verifies its next request is limited.

## C1 — baseline before matcher optimization

Added a dependency-free release-mode benchmark covering route counts 10–10,000,
hits/misses/build, header key/plan, rate lookup, RS256 verification, upstream
selection and literal warm DNS. Full-run resource measurements and raw samples
are committed in docs/performance. An initial upstream fixture omitted required
routes; after fixing that fixture the complete benchmark exited successfully.
The host C compiler cache was read-only; disabling ccache allowed release builds.
No whole-gateway throughput or HTTP latency is inferred from microbenchmarks.

## C2–C3 — route index and request-path allocations

Segment trie for tables above 32 routes (`routes/index.rs`), equivalence-tested
against the linear predicate; `prefix_candidates` (explain/why-not) unchanged.
p50 at 10,000 routes: hit 35.5 us -> 0.46 us, miss 70.3 us -> 0.08 us; build
about 30% slower. `match_request` no longer allocates for an already
upper-case method / lower-case host (about 10 ns per lookup). Data in
docs/performance.

## D1 — hostname pools and opt-in discovery (item 13)

Confirmed bug: Pingora 0.9 `Backend::new` parses socket addresses only, so any
hostname pool target (the README example) failed at startup. Fixed: every
resolved address becomes a member carrying its target index; the proxy dials
the selected address. Opt-in `discovery: {interval, max_members}` refreshes in
the balancer's background service; failed/empty/oversized/ambiguous answers
keep the last good set. `gateway_upstream_discovery_total` counts outcomes.
Not covered end to end: `localhost` is dual-stack and the Python members bind
IPv4 only, so unit tests (scripted resolver, real LoadBalancer) cover it.

## E1 — CI, supply chain, version

Actions pinned by SHA (all 12 verified with `git ls-remote`), toolchain 1.98.0,
`--locked`, feature combinations, least-privilege release token, provenance for
archives and image manifest lists (attestation steps unverified until a tagged
release runs). Fresh `cargo deny` found three advisories; patched. Workspace,
lockfile and starter images bumped to 0.1.9 (images not yet published).

Final checks at the branch tip (this session): `cargo fmt --check`, `cargo clippy
--locked --workspace --all-targets -D warnings`, lean clippy, `cargo test
--locked --workspace` (462 passed), lean lib tests (407 passed), feature checks
(shared-limits, cache, otel), `cargo deny check` (online), `tests/e2e/run.sh`
(218 passed, 0 failed).

Items 9, 12, 14, 16, 18 and 20 were then completed in the session below.

## F — remaining items (second pass)

| Item | Outcome |
| --- | --- |
| 18. Branch protection | Read-only API check: no protection or rulesets on `main`, `v*` tags unprotected, no release environment, secret scanning off. Nothing changed; exact `gh api` steps in docs/repository-protection.md. |
| 9. Replicas | docs/deploying.md "Running several replicas" table: what is per process (caps, breakers, cache, keys, pool health, accept limits, reloads) and the shared-counter modes. |
| 20. Docs | SECURITY known gaps corrected (deadline, CSRF, JWKS stale were listed as missing); ROADMAP "Next" replaced with open items; README links the new controls and fixes its "no CSRF check" claim. |
| 16. Errors | Confirmed: JWKS `max-age` was uncapped (revoked keys trusted and rotated keys refused for as long as advertised; `u64::MAX` overflowed into refetch-per-request) — capped at 24h. Token `kid`/`iss` were logged verbatim (log-line forging in text format) — escaped and truncated. `connect * 2` per request — saturating. Metric labels were already normalized. |
| 14. Cache | Confirmed: concurrent fills on distinct keys buffered outside `max_size` — new `cache.max_inflight_fill` (64 MiB). Cache bench added; binary-hash keys cut miss lookups 578 -> 256 ns. |
| Shutdown | Found while benchmarking, confirmed by timing: SIGTERM waited Pingora's 300s default and `graceful_shutdown` never drained (tokio cancels async tasks at runtime shutdown). Fixed; e2e `shutdown.py` fails on the old build. |
| 12. Hot path | Whole-gateway harness (benches/http). No Lagos function above 2.5% of CPU; levers are RSA verification (27% on JWT traffic), the allocator (17–22%) and logging. jemalloc A/B: +5 to +15% throughput, -6% RSS — measured, not adopted (C dependency in release builds). |
| 15. Architecture | Not refactored. `request_filter` (685 lines) is the single authorization boundary in labelled sequential phases; splitting it into phase methods is a reasonable follow-up PR on its own, not part of security fixes. |

Final checks at the branch tip: `cargo fmt --check`; clippy (workspace and
lean, `-D warnings`); `cargo test --locked --workspace` 467 passed; lean lib
411 passed; shared-limits/cache/otel checks; `cargo deny check` online clean;
`tests/e2e/run.sh` 219 passed, 0 failed.

Recommended follow-ups, each its own PR: jemalloc (with release-build
verification on musl/arm64), verified-token cache design, `request_filter`
phase extraction, applying docs/repository-protection.md, and
`CacheMeta` reuse if pingora-cache makes it `Clone`.
