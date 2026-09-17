# Upgrading

Only `main` is supported pre-1.0 (see [SECURITY.md](SECURITY.md)). This file
records the changes that alter behaviour on upgrade, so a deployment can be
moved forward deliberately rather than discovered in production.

---

## 0.1.3 → 0.1.4 — CLI developer experience and pool health checks

Standalone Linux/macOS CLI downloads are available starting with this release,
alongside existing Docker images. The optional installer requires no Rust or Cargo;
prebuilt Linux targets use static musl linkage and macOS targets require 14+.
Version pinning and SHA-256 verification are included. No Windows native
download is included. See
[installation](docs/installation.md). Source builds and Docker use remain
available, and binary distribution does not change gateway configuration.

Existing gateway configuration remains valid without `defaults:`. `lagos init`
now generates a minimal one-route file; use `examples/gateway.yml` for the full reference. The new
`lagos init --docker`, `lagos test`, and `lagos diff` commands are optional.
The new `lagos init --docker --extensions` starter and matching builder image
are also optional. Existing custom binaries can keep calling `Cli::run`; only
convention-based builds use `Cli::run_with_extension_names` to check names
without constructing extensions during `validate --allow-unset`.

`lagos schema`, `lagos schema --routes`, and `init --schema` are optional editor
tools. Official release images add a version-pinned schema comment to generated
YAML; local/source builds can select a local schema. Existing configuration files
and proxy behavior are unchanged by schema support. Update schema references
alongside image upgrades; see [editor setup](docs/configuration-editor.md).

`lagos vars [CONFIG]` is an optional environment inventory command. It works
with missing variables, hides values and defaults, and reports unchecked route
files. It does not change runtime interpolation or configuration validation;
see [variable diagnostics](docs/configuration-vars.md).

`lagos explain --why-not` and `--listener public|internal` are optional diagnostic
flags; the default listener remains public. Explanations now report unchecked
runtime work and handle local health paths and query strings consistently with
the proxy. Injected header names follow the selected listener. No request-handling
behavior changes; see [route explanations](docs/route-explanations.md).

`lagos config --effective [CONFIG]` is an optional redacted offline JSON view.
It uses current inputs rather than the serving process's snapshot, requires a
resolvable configuration, and marks extension introspection unchecked. Its
output is unsuitable for deployment. Runtime configuration and request handling
are unchanged; see [effective configuration](docs/effective-configuration.md).

Optional top-level `defaults:` shares `methods`, `retry`, and `rate_limit`.
Omitted route fields inherit; explicit `retry: null` or `rate_limit: null`
disables the inherited policy. `methods: []` explicitly allows any method;
`methods: null` remains invalid. Route mappings replace entire policies, so
required fields cannot be supplied by defaults. Auth, caching, and listeners
cannot be defaulted. Restart after changing top-level defaults; external
route-file overrides still reload and invalid changes keep the last valid table.
`diff` reports inherited policy changes, and diagnostic tools show their origins.
See [route defaults](docs/route-defaults.md).

Custom Rust code constructing `RouteConfig` with struct literals must now set
`policy_origins`, normally with `Default::default()` for explicit policies.
Custom `GatewayConfig` struct literals also need `defaults: Default::default()`.
Existing deserialization and route-provider constructors remain available;
custom providers can call `RouteTable::build_with_defaults` to opt into global
inheritance. Stock gateways and the conventional `ext/` starter handle this
without application changes.

Pool HTTP health checks now use each target's Host header, including its port,
scheme, and TLS server name. Previously, every member inherited the first
target's settings, which could incorrectly remove healthy members from rotation.
The configured health-check path still applies to every member as written.

Pool targets that resolve to the same address and port now prevent startup.
Previously, their target settings could silently overwrite one another. Remove
duplicate entries and use a single target's `weight` to express its traffic
share. Separate logical upstreams are needed when different authorities share
the same socket address. Pool DNS membership remains fixed at startup.

---

## 0.1.2 → 0.1.3 — request-path hardening

Every new setting has a default, so an existing `gateway.yml` still parses and
still starts. Three of those defaults change what the gateway *does*. Read the
first one before deploying.

### 1. `X-Forwarded-For` from an untrusted hop is now discarded

**This is the one that can change what your upstreams see.**

Before, the gateway relayed whatever `X-Forwarded-For` arrived and derived
`X-Real-IP` from its **leftmost** entry. That entry is written by whoever sent
the request, so any caller could assert any source address with one header —
and every downstream control keyed on client IP (per-IP quotas, geo rules, fraud
scoring, abuse blocklists, audit trails) believed it.

Now the gateway counts from the right, the same way `rate_limit.trusted_proxies`
already did, and the new `forward.trusted_proxies` says how many hops in front
of it are yours:

```yaml
forward:
  trusted_proxies: 1   # new; defaults to 0
  trusted_proxy_ips: [10.1.2.3/32]  # source addresses of your proxy peers
```

| `trusted_proxies` | Arriving chain | `X-Real-IP` sent upstream |
|---|---|---|
| `0` (**the default**) | discarded | the socket peer |
| `1` | untrusted prefix removed, peer appended | the entry your one proxy appended |
| `2` | untrusted prefix removed, peer appended | one further left |

**What to do.** Count the hops between the internet and the gateway that you
operate, and set `forward.trusted_proxies` to that number.
List their source addresses or CIDR ranges under `forward.trusted_proxy_ips`.
Lagos refuses a trusted-hop configuration without this list; a direct caller
must not be able to impersonate a proxy by supplying XFF.
Use narrow ranges and restrict the listener to those proxies at the network
layer; any host allowed to connect from a listed address can supply XFF.

- **Behind an ingress controller, cloud load balancer or service mesh** — the
  usual Kubernetes deployment — set it to `1`. Leaving it at `0` is safe but
  changes behaviour: upstreams will start seeing the *ingress pod's* address
  as the client. Anything keyed on client IP downstream will silently begin
  grouping every caller together.
- **Behind a CDN in front of a load balancer**, set it to `2`.
- **If the gateway is the edge**, leave it at `0`. That is now correct by
  default rather than by configuration.

Set it too high and the forgery is back: a client pads the chain until its own
entry lands on the hop you said to trust. Count the hops, do not round up.

The gateway logs `gateway.forward.untrusted_chain` once at boot when the value
is `0`, and `lagos validate` prints the policy in effect.

**Order matters.** `forward` is declared `deny_unknown_fields`, so a 0.1.2
binary reading a config that contains `trusted_proxies:` **refuses to start** —
it is a parse error, not an ignored key. The binary and the config line must
land together:

1. Deploy the new binary with the config unchanged. It starts, and behaves as
   `trusted_proxies: 0` — safe, but upstreams see the ingress address.
2. Add `forward.trusted_proxies` and `forward.trusted_proxy_ips` and roll again.

Do not add the line first, and do not roll back to 0.1.2 with the line still in
place.

`rate_limit.trusted_proxies` is unchanged and still per-route. The two should
agree — throttling one address while telling the upstream about another makes a
per-IP control unenforceable. An IP rate limit that trusts a proxy also requires
`forward.trusted_proxy_ips`.

### 2. Downstream connections now have time and request budgets

Pingora leaves most downstream limits unset, which for an edge gateway means
unbounded. New defaults:

```yaml
timeouts:
  downstream_read: 30s        # absolute header deadline; body read-stall limit
  downstream_write: 30s       # was unset — unbounded
  downstream_drain: 5s        # was unset — unbounded
  downstream_keepalive: 60s

limits:
  keepalive_requests: 1000    # was unset — unbounded
  min_send_rate: null         # off, as before
```

A client that connected, sent a request slowly, then read the response slowly
previously held a worker task and an upstream connection for as long as it
liked, at a cost to the attacker of one socket.

**What to do.** Nothing, in most cases. Two situations deserve a look:

- **SSE routes** are handled: a route with `sse: true` gets `timeouts.sse` as
  its write budget instead of `downstream_write`. If your event streams already
  worked, they still do.
- **Very slow clients on poor links** uploading large bodies. The read timeout
  is per read operation for bodies, so a 30s gap between chunks trips it.
  Headers must complete within 30s total. Raise `timeouts.downstream_read` if
  your clients need it.

`min_send_rate` stays off, since a real client on a bad link is not an attacker.

### 3. A rejection that used to be `503` is now `401`

A verified token whose `sub`, `iss` or a mapped claim contains something that
cannot be a header value — a control character, a non-ASCII subject — is now
refused as `401 invalid_token: unrepresentable_identity`. It previously either
became `503 identity_mint_failed` or reached the HTTP stack and came back as a
`502` blaming the upstream.

Nothing that worked before starts failing: this is a request that was already
refused, answered with the right status. It matters because a `503` tells a
client to retry the one thing that can never succeed, and pages an operator for
a malformed credential.

### 4. Route files stay beside their configuration, and ambiguous routes fail

A relative `routes.file` path now resolves beside `gateway.yml` even if a file
of the same name exists in the working directory. This prevents a working
directory file from silently replacing the route and authentication policy in
the configuration directory. If you intentionally keep the route file elsewhere,
give `routes.file` an absolute path.

Routes with the same prefix and overlapping host and method matchers now fail
validation when they could depend on declaration order or cross authentication
tiers. A public route at `/secret` could previously shadow an authenticated
route at `/secret` if both had distinct ids. Give them distinct paths, hosts or
methods, or remove the unintended route. A host-specific override of a
catch-all on the same tier remains supported.

### Also in this release, with no configuration change

- **`limits.max_token`** (default `8KiB`) caps the bearer token the gateway will
  look at. Finding a token's issuer means base64-decoding and parsing it, and a
  recognised issuer then costs a public-key signature check — all before any
  identity-keyed limit can apply. Over-length tokens are `401`, not treated as
  absent, so an `optional` route reports the problem instead of silently serving
  the caller anonymously.
- **Rate limits keyed on `ip`, `header` or `route` are now applied *before*
  token verification**, so an unauthenticated flood of well-formed,
  badly-signed tokens is throttled rather than being refused only after each
  signature check has been paid for. `identity` keys still run after
  verification, because that is the earliest a subject exists. Quotas and keys
  are unchanged.
- **Secrets no longer appear in `Debug` output.** `MachineConfig` and
  `IdentityTokenConfig` print `<redacted N bytes>`. `ResolvedConfig` derives
  `Debug`, so one `tracing::debug!(?cfg)` used to be enough to put the
  machine-tier credential and the identity signing key in a log.
- **Fetched key sets are capped at 1 MiB.** A compromised or broken JWKS
  endpoint could previously return an unbounded body into memory.
- **Route and deny-list matching no longer allocates per candidate route.** This
  ran on every request and grew with the size of the route table. Matching
  semantics are unchanged — still an exact match or a `/`-delimited prefix.

### Library callers

Three signatures changed. Only code embedding `lagos-core` is affected; the
binary and its configuration are not.

| | Before | After |
|---|---|---|
| `headers::forwarded_for` | `(&HeaderMap, Option<&str>)` | `(&HeaderMap, Option<&str>, usize)` — trusted hops |
| `identity::apply` | `Result<(), String>` | `Result<(), IdentityError>` — `Claim` (401) vs `Mint` (503) |
| `ratelimit::client_address` | defined here | re-exported from `headers`, same signature |
