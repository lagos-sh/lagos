# Roadmap

Direction, not dates. Lagos is pre-1.0 and maintained by a small team, so this
is what is being worked toward and what is deliberately out of scope — ordered
by conviction, not by quarter.

What already works is in [Features](README.md#features). What changed in each
release is in [CHANGELOG.md](CHANGELOG.md). Security controls and their known
gaps are in [SECURITY.md](SECURITY.md).

Configuration DX includes [editor setup](docs/configuration-editor.md), schema
generation, variable inventory, route explanations, redacted effective output,
and route defaults, all available starting with 0.1.4.
Optional partner credentials are a separate feature.

Standalone Linux/macOS binaries and an automatic installer are available
starting with 0.1.4; see [installation](docs/installation.md). Windows native
support remains future work.

---

## Next

Ordered roughly by how often the absence bites.

| | Why |
|---|---|
| **Distributed rate limiting** | Counters are per process today: 100/min across three replicas admits 300/min. Fits behind the existing `Limiter` interface |
| **Stale-while-error on JWKS** | An identity provider outage currently stops authenticated traffic, even though the cached keys were almost certainly still valid |
| **Total request deadline** | Timeouts are per read, per write and per connect. A client making slow but steady progress stays inside all of them indefinitely |
| **Extension execution budgets** | Lagos must bound each request hook and the complete extension chain, reject on timeout, and report which policy exceeded its budget. Native hooks remain trusted code; asynchronous timeouts cannot preempt blocking code. See the [extension proposal](docs/extension-hardening.md) |
| **In-flight concurrency cap** | Bound the requests being worked on at once, independently of rate, and shed load rather than queue it when saturated |
| **Request header size limit** | Whatever Pingora's parser accepts, the gateway accepts. Should be ours to bound |

---

## Later

Real direction, no commitment. Each needs the layer beneath it to settle first.

- **Passive health checking** — eject an individual backend on observed failures, rather than only opening the whole upstream's circuit
- **Traffic splitting** — weighted routing across *services* for canary and blue/green. Weights exist within a pool today; splitting across two upstreams does not
- **OpenAPI import** — generate routes, methods and security requirements from a contract. The strongest single differentiator available to this project, and the largest piece of work
- **Request validation** — query, header and body schemas, so invalid requests never reach an application
- **Simple policy decisions** — an optional allow/deny API for checks, with errors distinct from denial; retain the existing extension API for trusted header enrichment. See the [extension proposal](docs/extension-hardening.md)
- **Language-independent HTTP checks** — invoke an application-owned policy endpoint written in any language, using a versioned context/decision contract and gateway-enforced deadlines and concurrency limits. This is an optional service, not arbitrary scripts loaded into the gateway. See the [extension proposal](docs/extension-hardening.md)
- **Route providers beyond files** — the `RouteProvider` seam already exists; a provider watching Kubernetes `Ingress`/`HTTPRoute` would not change the proxy path
- **Downstream TLS and HTTP/2** — today termination belongs at an ingress. Enabling h2 here means tuning Pingora's `H2Options` for the Rapid Reset family
- **WASM policies** — only once the policy contract is stable enough to freeze into an ABI, with execution and memory limits and bounded host calls. Language support depends on compatible toolchains; HTTP checks come first. Native dynamic plugins are not the answer; a half-designed WASM interface is not either
- **Optional control plane** — central config, revisions, rollback, fleet status. Hard rule if it ever exists: **gateway traffic must continue when the control plane is unavailable**, and it must never sit on the request path
- **Secret zeroization** — `Debug` is redacted, but secrets are ordinary `String`s in memory

---

## Not planned

Not because they are bad, but because they would make this a different project:

service mesh · WAF · CDN · identity provider · developer portal · API monetization
or billing · API marketplace · Kubernetes operator · GraphQL or AI gateway ·
dashboard · a mandatory database, Redis or control plane

Lagos decides **who may reach a route** and **what the upstream is told about
them**. It does not inspect what is sent through it.

---

## The road to 1.0

1.0 means the configuration format is stable and breaking changes get a
deprecation period. Getting there needs:

- The configuration surface reviewed once, deliberately, for things that would be painful to keep
- `validate` / `explain` / `diff` covering enough that a config change can be reviewed without reading Rust
- Security review of the request path by someone who did not write it

Until then, pin a tag and read [UPGRADING.md](UPGRADING.md) before moving
forward.

---

## Influencing this

Roadmap items move when someone needs them. A use case Lagos cannot serve is
more useful than a feature request — open an issue describing the problem, not
the solution you have in mind. See [Contributing](README.md#contributing).
