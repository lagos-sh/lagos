# Extension hardening and language-independent checks

Status: roadmap proposal, not implemented in 0.1.4. Configuration names, numeric
defaults and the wire contract need review before implementation.

Extensions run on the request path. A slow application lookup or unfinished
check must not make Lagos wait indefinitely or forward a request whose required
policy has not approved it. Small teams should also be able to write simple
checks without maintaining a custom Rust gateway binary.

## 1. Gateway-enforced execution budgets

Every request hook should have an effective finite deadline, enforced by Lagos
rather than relying only on an extension author's HTTP or database timeout.

- Supply a finite default so existing applications do not need new mandatory
  configuration. Choose its value using measured latency and compatibility
  testing; a small universal limit such as 100ms could break live lookups.
- Allow a shorter budget per named extension, subject to an operator-configured
  maximum. Reject zero, unlimited and inconsistent budgets during validation.
- Bound the entire extension chain as well as each hook. Several individually
  bounded hooks must not accumulate unlimited request latency. Include waiting
  for extension capacity in the budget; use the remaining total request deadline
  once that separate roadmap feature exists.
- Execute hooks in declared order. On a rejection, error or expired budget,
  stop the chain and do not contact the route's upstream. Commit trusted header
  changes only after the required policies succeed.
- Treat deadline expiry as an unavailable policy decision, proposed HTTP 503,
  rather than a business denial or permission to continue. Existing explicit
  native rejections keep their semantics.
- Record per-extension duration, timeout and rejection metrics with bounded
  labels. Logs identify the route and extension without recording credentials
  or raw claims. CLI validation and explanations should show effective budgets.

The limit covers request hooks. Extension construction at startup needs separate
lifecycle guidance; constructors should not perform unbounded remote work.

### What a native timeout can guarantee

An asynchronous timeout can stop waiting on a cooperative future by dropping it.
It cannot forcibly interrupt synchronous blocking code or an infinite CPU loop
in a hook. A timed-out call also does not undo work already sent to another
service or automatically stop detached background tasks.
[Tokio documents this timeout limitation](https://docs.rs/tokio/latest/tokio/time/fn.timeout.html).

Native extensions therefore remain privileged, trusted Rust code. Require
nonblocking request hooks, bounded I/O and tracked cancellation. Moving work to
a blocking thread alone does not make that work interruptible. Stronger CPU,
memory and crash isolation needs a separate process or sandboxed runtime.
Document this distinction instead of promising an absolute maximum execution
time for arbitrary native code.

## 2. A simple decision API alongside enrichment

For validation-only policies, offer a convenience interface whose successful
result is a boolean: `true` allows the request and `false` denies it. Preserve
an error channel, conceptually `Result<bool, Error>`, so an unavailable check
is distinguishable from a confirmed denial.

| Outcome | Lagos behavior |
|---|---|
| Allow | Continue to the next required policy |
| Deny | Reject, proposed HTTP 403 |
| Error, timeout or malformed decision | Reject as unavailable, proposed HTTP 503 |

A boolean-only interface cannot represent lookup failure or trusted header
enrichment. Keep the existing `Extension` interface compatible: tenant/company
lookups can both validate access and populate upstream context. A simple check
must not change verified identity, bypass authentication or override a prior
denial. Every required check must allow before forwarding.

## 3. Language-independent checks through HTTP

Start with an optional HTTP policy adapter. Teams run their own small check
service using any language that can serve HTTP and JSON. Lagos sends a minimal
request context after authentication and receives a structured decision, for
example `{"allow": true}`. SDKs may let application developers return just a
boolean while the adapter handles protocol details and exceptions.

The convention should define:

- A versioned, bounded input containing the canonical path, method, route and
  selected verified identity claims or client fields. Do not automatically send
  bearer tokens, gateway credentials, entire headers or request bodies.
- Strict response validation: require a literal boolean decision. An HTTP 200,
  empty body or arbitrary truthy value is not approval. Error responses and
  invalid payloads remain unavailable decisions.
- Operator-configured endpoints, service authentication and appropriate
  transport protection. Request data must not choose the policy endpoint;
  policies must know the context came from the trusted gateway.
- Gateway-enforced deadlines, connection reuse, bounded payloads and an in-flight
  capacity limit. Shed load instead of building an unbounded queue. Avoid
  automatic retries initially; a check may already have performed remote work.
- An optional local sidecar/Compose service and starter example. Rust and
  `lagos-builder` are unnecessary for this mode: the stock image supplies the
  HTTP adapter, while the team supplies the policy service and YAML settings.

The gateway can bound how long it waits for an HTTP decision, but cannot stop
arbitrary work in a remote service. That service needs its own resource limits
and cancellation handling. This mode adds a network hop and a service to operate;
inline Rust remains useful when a team already owns a custom image.

Keep HTTP checks decision-only initially. Any later context/header output needs
a separate, explicit allowed-header contract before it can modify upstream
authority.

## 4. Sandboxed local policies later

Consider WebAssembly once the decision contract is stable and there is demand
for local policies without a separate HTTP service. Require CPU execution
limits, memory limits and separately bounded host I/O. Wasmtime supports
[fuel and epoch interruption](https://docs.wasmtime.dev/examples-interrupting-wasm.html),
which can interrupt guest computation; this does not by itself bound every
host operation.

Promise supported language/toolchain combinations, rather than claiming that
every existing language or script can run unchanged. Do not embed an unrestricted
shell or add one language interpreter per policy to the gateway.

## Validation before shipping

Exercise slow cooperative hooks, chain deadline exhaustion, saturation and
rejection before forwarding using isolated fixtures. Verify that timed-out or
rejected hooks never forward partially enriched headers. Preserve existing
native extension behavior and test applications whose dependency timeout is
longer than the new gateway budget.

For HTTP checks, test allow, deny, service outage, malformed responses, oversized
payloads and capacity exhaustion. Use equivalent fixtures in at least two
languages to demonstrate that the wire contract works without a Rust application
build. Blocking native hooks remain a documented isolation limit, not a guarantee
that asynchronous timeout tests can establish.
