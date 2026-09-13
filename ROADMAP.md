# Roadmap

Direction, not dates. Lagos is pre-1.0 and maintained by a small team, so this
is what is being worked toward and what is deliberately out of scope — ordered
by conviction, not by quarter.

What already works is in [Features](README.md#features). What changed in each
release is in [CHANGELOG.md](CHANGELOG.md). Security controls and their known
gaps are in [SECURITY.md](SECURITY.md).

---

## Next

Ordered roughly by how often the absence bites.

| | Why |
|---|---|
| **Production validation** | Load and soak testing, memory behaviour under sustained traffic. The single biggest gap between "tested" and "trustworthy" — see [Project status](README.md#project-status) |
| **`lagos diff old.yml new.yml`** | Configuration is infrastructure-as-code; a reviewer needs to see what a PR actually changes to the route surface, not to the YAML |
| **`lagos test`** | Assert routing and policy outcomes without upstreams. Unit tests for gateway configuration |
| **Distributed rate limiting** | Counters are per process today: 100/min across three replicas admits 300/min. Fits behind the existing `Limiter` interface |
| **Stale-while-error on JWKS** | An identity provider outage currently stops authenticated traffic, even though the cached keys were almost certainly still valid |
| **Total request deadline** | Timeouts are per read, per write and per connect. A client making slow but steady progress stays inside all of them indefinitely |
| **Request header size limit** | Whatever Pingora's parser accepts, the gateway accepts. Should be ours to bound |

---

## Later

Real direction, no commitment. Each needs the layer beneath it to settle first.

- **Passive health checking** — eject an individual backend on observed failures, rather than only opening the whole upstream's circuit
- **Traffic splitting** — weighted routing across *services* for canary and blue/green. Weights exist within a pool today; splitting across two upstreams does not
- **OpenAPI import** — generate routes, methods and security requirements from a contract. The strongest single differentiator available to this project, and the largest piece of work
- **Request validation** — query, header and body schemas, so invalid requests never reach an application
- **Route providers beyond files** — the `RouteProvider` seam already exists; a provider watching Kubernetes `Ingress`/`HTTPRoute` would not change the proxy path
- **Downstream TLS and HTTP/2** — today termination belongs at an ingress. Enabling h2 here means tuning Pingora's `H2Options` for the Rapid Reset family
- **WASM policies** — only once the extension API is stable enough to freeze into an ABI. Native dynamic plugins are not the answer; a half-designed WASM interface is not either
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

- A real production deployment, and load/soak results to go with it
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
