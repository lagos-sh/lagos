# Security policy

Lagos is a trust boundary. Every service behind it has stopped checking who the
caller is, because the gateway already did — so a bug here is not a bug in one
application, it is a bug in the thing all of them are relying on. Please report
anything you find.

## Reporting a vulnerability

**Use [GitHub's private vulnerability reporting](https://github.com/lagos-sh/lagos/security/advisories/new).**
It opens a channel visible only to the maintainers, and it works without
exposing an email address or asking you to encrypt anything.

Please do **not** open a public issue for a suspected vulnerability. A public
issue describing an authentication bypass is a working exploit handed to
everyone running the gateway before there is a fix to run.

A useful report has: what you sent, what came back, what you expected instead,
and the configuration it happened under. A failing `curl` is worth more than a
paragraph of description.

### What to expect

This is an early-stage project with a small maintainer team, so these are honest
expectations rather than a service level agreement:

| | |
|---|---|
| Acknowledgement | within a week |
| Assessment, and whether it is in scope | within two weeks |
| Fix for a confirmed critical issue | as fast as it can be done properly |

There is no bug bounty. Credit in the advisory and the release notes is offered
for every valid report, and declined gracefully if you would rather stay
anonymous.

## Supported versions

Pre-1.0, only `main` is supported. There are no maintenance branches and no
backports — fixes land on `main` and are released from there. If you are running
a tagged version, be ready to move forward to get a fix.

## What counts as a vulnerability

Lagos makes a small number of specific promises. A way to break any of them is a
vulnerability, and these are the ones worth attacking:

- **Identity cannot be forged.** A client must not be able to make an upstream
  see identity headers it did not earn — not by sending them directly, not
  through casing or duplication tricks, not through header smuggling.
- **A refused request stays refused.** No path encoding, traversal sequence,
  normalization difference or routing quirk should reach an upstream that the
  deny-list or allowlist was supposed to protect.
- **A token is verified properly.** Expired, wrong-audience, wrong-issuer,
  foreign-key, `alg:none`, and swapped-payload tokens must all fail.
- **Credentials do not leak.** Injected upstream credentials must never appear
  in a response, a log line, an error body or a trace.
- **One caller's response is not served to another.** Anything that makes the
  response cache return a personalised or authorized response to a different
  caller is critical.
- **Refusals are indistinguishable.** A caller must not be able to tell a
  deny-listed path from a path that does not exist — that difference is how a
  deny-list gets mapped.
- **Limits hold.** A way to bypass rate limiting, or to make the gateway consume
  unbounded memory with a well-formed request, is in scope.

## What the gateway enforces today

A quick map of where each control lives, so a report can point at code and a
reviewer knows what is already covered.

**Identity**

- Tokens verified against configured issuers; `alg` matched against an operator
  list *before* any key is fetched, so `alg:none` and RSA-as-HMAC do not reach a
  verifier — [`auth/jwt.rs`](crates/lagos-core/src/auth/jwt.rs)
- Audience required; an issuer with no configured audience is refused rather
  than assumed
- `exp`, `nbf` and `iat` all checked, `iat` explicitly because `jsonwebtoken`
  does not
- Identity headers always `set` (which strips first), never merged, so no
  casing or duplication trick survives — [`headers.rs`](crates/lagos-core/src/headers.rs)
- Public routes strip every identity header, including mapped claim headers
- Claims that cannot be a header value are refused before any header is built
- Machine credentials compared in constant time
- Machine routes live on a separate listener, so they are absent from the public
  gateway rather than merely guarded on it

**Request surface**

- Paths fully percent-decoded (three passes, defeating `%252e`), then dot
  segments, backslashes, control characters and leftover `%` rejected —
  [`path.rs`](crates/lagos-core/src/path.rs)
- Deny-list applied before route matching, and every refusal answers `404` so
  the internal surface cannot be enumerated
- Hop-by-hop headers stripped; `Content-Length`/`Transfer-Encoding` conflicts are
  resolved by Pingora before the gateway sees them
- Ownership bindings refuse duplicate query parameters in every spelling, so
  parameter pollution cannot split the check from the upstream's reading of it —
  [`binding.rs`](crates/lagos-core/src/binding.rs)
- CORS origins matched whole; `credentials: true` with `*` refused at startup;
  `Vary: Origin` always set when an origin is echoed

**Limits**

- Request bodies capped by declared length and by streamed bytes
- Bearer tokens capped before being decoded or verified
- Rate limits keyed on IP, header or route applied *before* token verification
- Client address counted from the right of `X-Forwarded-For` only for allowlisted
  proxy socket peers; untrusted prefixes are removed before forwarding
- Absolute request-header deadline and downstream read, write, drain and
  keepalive budgets set, plus a per-connection
  request limit — Pingora leaves most of these unbounded
- Optional per-address connection rate limit at accept time, before a connection
  costs a task or a handshake
- Optional TCP keepalive, so a vanished peer releases its socket
- Rate-limit key store bounded and TTL'd; fetched key sets capped
- `unsafe_code = "forbid"` workspace-wide; clippy warns on `unwrap`, `panic` and
  indexing, and CI runs it as `-D warnings`

## Known gaps

Honest, not exhaustive. These are known and not yet done; a report that one of
them is exploitable in a way described here is still welcome, but it will not be
news.

- **No cap on *concurrent* connections.** `limits.connections_per_ip` bounds how
  fast one address may open them, while the header deadline closes sockets
  that never finish a request — but Pingora's accept hook is never told about
  a close, so a live count cannot be kept honestly from there. A hard ceiling
  still belongs at the ingress (`limit_conn`) and in `ulimit`.
- **A per-address limit is the wrong control behind a proxy.** Where every
  connection arrives from one ingress address, enabling it would throttle the
  whole gateway. It is off by default for that reason, which means the default
  deployment has no connection control of its own.
- **No request-header size limit of our own.** Whatever Pingora's HTTP/1
  parser accepts, the gateway accepts. Bound it at the ingress.
- **No total-request deadline.** The timeouts are per read, per write and per
  connect. A client that makes slow but steady progress can stay well inside all
  of them for a long time.
- **No downstream TLS and no HTTP/2 on the listener.** Terminate at an ingress.
  If plaintext h2 is ever enabled here, Pingora's `H2Options` (stream and
  header-list limits, and its malformed-stream budget) will need tuning for the
  Rapid Reset family — today they are simply not reachable.
- **Rate limiting is per process.** A limit of 100/min across three replicas
  admits up to 300/min. A shared backend fits behind the same `Limiter`
  interface; nothing implements one yet.
- **No stale-while-error on JWKS.** If an identity provider is unreachable when
  the key cache expires, verification fails closed and authenticated traffic
  stops, even though the cached keys were almost certainly still valid.
- **Secrets are ordinary `String`s in memory.** `Debug` is redacted, but there
  is no zeroization and no `mlock`. A core dump or a heap read finds them.
- **No request-body inspection.** No WAF, no schema validation, no content
  scanning. The gateway decides who may reach a route, not what they may send
  through it.
- **`forward: passthrough` mode is exactly what it says.** Every client header
  reaches the upstream. The allowlist default exists because that is the safe
  one.

## What does not count

- **Misconfiguration.** Setting `trusted_proxies` higher than the number of
  proxies actually in front of the gateway lets a client forge its own address.
  That is documented, validated where it can be, and still the operator's
  decision — it is not a vulnerability in Lagos. The same applies to allowlisting
  a header that should not have been allowlisted, or enabling
  `cache_authenticated` on a route whose upstream sends wrong `Cache-Control`.
- **Volumetric denial of service.** Enough traffic will exhaust any gateway.
  A single request that costs disproportionate memory or CPU *is* in scope; a
  million ordinary ones are not.
- **Vulnerabilities in dependencies**, unless Lagos's use of them is what makes
  the issue exploitable. Report those upstream — though telling us as well is
  appreciated, so the dependency can be bumped.
- **Anything that requires write access to the configuration.** Whoever can edit
  `gateway.yml` already decides what the gateway does.

## Disclosure

Coordinated. We will agree a date with you, publish a GitHub advisory with a
CVE, and credit you unless you would rather we did not. If a report goes
unanswered for 90 days, publish — an unresponsive maintainer is not a reason to
leave users unaware.
