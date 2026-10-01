# Changelog

Behaviour changes and the config needed to preserve existing behaviour are in
[UPGRADING.md](UPGRADING.md).

## 0.1.7 — client address in the access log

- `gateway.access` and `gateway.upstream.error` log lines gain a `client_ip`
  field: the caller's address by the rule that fills `X-Real-IP` (the socket
  peer, or the address `forward.trusted_proxies` vouches for), or `-`. It is
  set before any refusal, so `401`, `404` and `429` lines name the caller too.
  The existing `client` field is unchanged: it is the client key id, not an
  address. No config change.

## 0.1.6 — client keys and token cookies

- Added `auth.token_cookies`, a list of cookie names a token may also be read
  from, for browser apps whose session token is an httpOnly cookie. The
  `Authorization: Bearer` header is always read first; a cookie is used only
  when there is no bearer header. Names are tried in order and matched exactly,
  and an empty value is no token. A cookie token is verified like a header
  token (invalid or expired → `401`, `optional` routes included), counts as
  authorized for the response cache, and with `forward.authorization: false` is
  removed from `Cookie` before proxying while other cookies pass. Off by
  default; nothing changes without it.

  Startup refuses `token_cookies` when no `jwt` or `firebase` verifier is
  configured, invalid cookie names, and duplicates. Every `gateway.access` log
  line gains a `credential` field (`header`, `cookie`, or `-`). `lagos
  validate` and `lagos explain` show where tokens are read from, `lagos diff`
  reports changes to the list, and editor schemas include the field. Lagos
  does no CSRF check for cookie tokens; see SECURITY.md.

- The `401` hints for a missing or invalid bearer token no longer name Firebase
  (`Use a fresh ID token from getIdToken().`, `Bearer <id_token>`). They now
  read `Refresh the token or sign in again, then retry.` and
  `Use: Authorization: Bearer <token>`, since any configured issuer can produce
  them. Only the `hint` text changed; status, `message`, `error` and the
  logged reason are the same.

- Added `auth.client_keys`, an optional gateway-wide key requirement. When it is
  configured, every route on the public listener — `public`, `optional` and
  `authenticated` alike — needs one of the configured keys in `x-client-key`
  (or the configured `header`); without it nothing changes. The health path and
  CORS preflights never need a key, the internal listener keeps the machine
  credential, and a missing or unknown key is a `401` with reason
  `missing_client_key` or `bad_client_key`.

  Keys are named (`keys: {storefront: ..., mobile: ...}`) so several can be live
  at once for rotation, and the id names the caller in the access log
  (a new `client` field, `-` when no key was needed) and in an optional
  `forward_as` header sent upstream. The key header is always removed before
  proxying, and `forward_as` is always cleared of any client-supplied value,
  exempt routes included. The internal listener is untouched.

  Routes are exempted explicitly, never by default: per route with
  `client_key: false`, by path prefix with `exempt`, or by group with
  `exempt_groups`. The check runs after IP-keyed rate limits, so key guesses
  spend the caller's budget, and before any bearer token is read. Keys are held
  as SHA-256 digests and compared in constant time against every configured
  key. Startup refuses keys under 16 bytes, keys with surrounding whitespace,
  two ids sharing a key, a `client_key` field when client keys are off, exempt
  prefixes that are not canonical, and a `header` or `forward_as` that the
  gateway already reads or writes (identity, injected, machine, forwarding and
  framing headers).

  `lagos explain` shows whether a request needs a key and why an exempt one does
  not, `lagos routes` lists key ids and exemptions and marks exempt routes
  `no-client-key`, `lagos test` can
  assert `expect.client_key: required | exempt | off`, `lagos diff` reports each
  route's requirement plus key ids and exemptions (never key values), and
  `lagos config --effective` reports the route field. Editor schemas include the
  new fields.

## 0.1.5

- Added per-route `strip_prefix`. When set, the matched route prefix is removed
  from the path sent upstream (`prefix: /svc/users` forwards `/svc/users/42` as
  `/42`, and the bare prefix as `/`); the query string is unchanged. It is off by
  default, so existing routes still preserve their prefix. Only the upstream
  request line changes: the deny-list, matching, bindings, cache keys, logs and
  metrics keep using the full canonical path, and matching stays on a segment
  boundary. `lagos explain` shows the forwarded path, `lagos routes` marks the
  route, `lagos diff` and `lagos config --effective` report the field, `lagos
  dev` narrates the forwarded path, and `lagos test` can assert it with
  `expect.upstream_path`. Editor schemas include the field.

## 0.1.4 — Docker starters and policy checks

- Prepared standalone stock CLI downloads for Linux/macOS on x86_64 and ARM64,
  packaged with licenses and SHA-256 checksums. A POSIX installer detects the
  platform, supports version pinning and custom destinations, and verifies
  downloads before replacing an existing executable. Native build/linkage,
  installer, schema, and proxy smoke checks run before publishing GitHub Release
  assets.

- Added optional top-level route defaults for `methods`, `retry`, and
  `rate_limit`, resolved identically for runtime, route-file reloads, and CLI
  tools. Omitted fields inherit; policy mappings replace whole fields; null
  disables retries/rate limits; empty methods allow any. Diagnostics show policy
  origins and defaults-only diffs. Top-level changes require restart. Editor
  schemas and upgrade guidance cover these semantics.

- Updated the locked `rustls` dependency to 0.23.45 to fix
  [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html),
  affecting TLS 1.3 handshake encryption boundaries.
- Added `lagos config --effective [CONFIG]`, an explicit redacted JSON projection
  of current input files and environment, with typed policy values, provenance,
  logical sources, and unchecked extension/runtime work. Credentials, URLs,
  paths, arbitrary strings, and interpolated settings are hidden. Diagnostic
  output is unsuitable for deployment and has no raw mode. Value-free errors
  share the variable-diagnostics policy.
- Added `lagos explain --why-not` to report all matching-prefix candidates and
  host, method, listener, or deny-rule exclusions using runtime matcher predicates.
  `--listener public|internal` selects the route partition (default public).
  Explanations distinguish route selection from unchecked runtime work, recognize
  local health paths, ignore query strings for routing, and use the selected
  listener's injected-header names.
- Added `lagos vars [CONFIG]` to inventory each environment reference with its
  set/defaulted/required state, default and required flags, and source line/column.
  It scans relative external route files, explicitly reports unchecked sources,
  and hides values, default text, and interpolated filenames in diagnostics.
- Added `lagos schema` and `lagos schema --routes` for YAML editor completion
  and input-shape validation, including custom input forms and typed environment
  interpolation. Committed schemas are checked for drift in CI and verified at
  versioned URLs before image release. `init --schema` selects a local schema;
  official release images generate a matching version-pinned editor comment.
- Fixed pool HTTP health checks to use each backend's Host, port, scheme, and
  TLS server name instead of reusing the first target's settings. Duplicate
  resolved backend addresses now fail startup instead of silently overwriting
  target settings.
- `lagos init` now writes a minimal one-route configuration; the larger
  configuration reference remains in `examples/gateway.yml`.
- `lagos init --docker` creates root-level `gateway.yml` and `Dockerfile`,
  pinning the image to the generating CLI's version. It checks both destinations
  before writing and requires `--force` to replace existing files.
- Added a copyable two-file example and Docker Compose/Kubernetes deployment
  guidance.
- `lagos test` checks offline request selection, auth tiers, listener isolation,
  and ownership bindings against a `gateway.test.yml` suite.
- `lagos diff` reports effective route-surface changes without printing upstream
  target values; it labels settings outside its scope and unchecked environment
  values.
- Added an optional `ext/` starter via `lagos init --docker --extensions` and a
  version-matched builder image that compiles its policy into a custom gateway
  binary without a handwritten entrypoint or Docker toolchain setup. The same
  builder runs extension unit tests with `lagos-build /work/ext test`.
- Convention-based extensions can declare their names for
  `validate --allow-unset`, so a build checks route references without
  constructing extensions or needing runtime secrets. Ordinary validation and
  serving still construct them.

## 0.1.3 — request-path hardening

### Added

- Configuration is discovered in `lagos/gateway.yml`, `deploy/gateway.yml` and
  `/etc/lagos/gateway.yml` as well as the previous locations, so an image can
  copy a configuration directory in and run with no arguments and no
  `GATEWAY_CONFIG`. `/etc/lagos` is tried last, so a file mounted over the
  working directory still overrides one an image baked in. Relative `routes.file`
  paths are always resolved beside their configuration document.
- `lagos validate --allow-unset` checks a document in an environment that does
  not hold production values — a container build, typically. An unset `${VAR}`
  with no default expands to a placeholder rather than failing, and every name
  treated that way is listed as unchecked. A declared default still wins over
  the placeholder, so `${PORT:-8080}` is checked as `8080`. Distinct unset names
  get distinct placeholders, avoiding false collisions in host-based routes.
  An environment-based `routes.file` path needs a default so the file can be
  checked at build time.

  Offered to `validate` alone. `run` and `dev` reject the flag: a gateway that
  started with a placeholder where a credential or an upstream belongs would be
  worse than one that refused to start.

  This makes a build-time check possible, which is the point:

  ```dockerfile
  FROM ghcr.io/lagos-sh/lagos:0.1.3
  COPY lagos/ /etc/lagos/
  RUN ["lagos", "validate", "--allow-unset"]
  ```

### Security

- Routes on the same prefix whose host and method matchers overlap are rejected
  when they could depend on declaration order or cross authentication tiers.
  A public route can no longer silently shadow an authenticated route with the
  same matcher.

- Client-supplied `X-Forwarded-For` is no longer trusted by default. `X-Real-IP`
  was derived from the leftmost entry, so any caller could forge its own source
  address. New `forward.trusted_proxies` counts trusted hops from the right.
- Downstream connections are now bounded: read, write, drain and keepalive
  timeouts, plus a per-connection request limit. Previously unbounded — slowloris
  and slow-read cost one socket each.
- Bearer tokens are capped (`limits.max_token`, 8 KiB) before being decoded,
  parsed or signature-checked.
- Rate limits keyed on `ip`, `header` or `route` now run *before* token
  verification, so an unauthenticated flood is throttled rather than paid for.
- Secrets no longer appear in `Debug` output; `MachineConfig` and
  `IdentityTokenConfig` print `<redacted>`.
- Optional per-address connection rate limit at accept time, via Pingora's
  `connection_filter` — refuses a flood before it costs a task or a handshake.
  Off by default: behind an ingress every connection shares one address.
- Optional TCP keepalive on accepted connections, so a peer that vanished without
  closing releases its socket instead of being held until a timeout notices.
- Fetched JWKS / certificate bodies are capped at 1 MiB.
- A verified token whose `sub`, `iss` or mapped claim cannot be a header value is
  refused before any header is built.
- Upstream names are resolved on the runtime's blocking pool and cached, not with
  a blocking `getaddrinfo` on a proxy worker thread per request. A slow resolver
  previously stalled every worker at once — a DNS wobble became a gateway outage,
  and slow DNS was an amplifier for anyone sending traffic.

### Changed

- Unrepresentable identity is now `401`, not `503` or a `502` from the HTTP stack.
- Over-length tokens are `401` rather than treated as absent, so an `optional`
  route reports the problem instead of silently serving anonymously.
- SSE routes use `timeouts.sse` as their downstream write budget.
- `lagos validate` prints the client-IP policy in effect; the gateway logs
  `gateway.forward.untrusted_chain` at boot when nothing is trusted.

### Performance

- Route and deny-list matching no longer allocates per candidate route on every
  request. Matching semantics unchanged.

### Config (all defaulted; existing files still parse)

- `dns.cache_ttl` — `30s` (`0s` resolves every request); `dns.max_entries` — `1024`
- `limits.connections_per_ip` — off; `limits.upstream_pool` — `128`
- `server.tcp_keepalive` — off; `server.shutdown_grace` — unset
- `forward.trusted_proxies` — `0`
- `limits.max_token` — `8KiB`
- `limits.keepalive_requests` — `1000`
- `limits.min_send_rate` — off
- `timeouts.downstream_read` / `downstream_write` / `downstream_drain` /
  `downstream_keepalive` — `30s` / `30s` / `5s` / `60s`

### API (embedding `lagos-core` only)

- `headers::forwarded_for` takes a trusted-hop count.
- `identity::apply` returns `IdentityError` instead of `String`.
- `ratelimit::client_address` re-exported from `headers`.
- `Interpolated` gains a `placeheld` field; `interpolate_with_fallback`,
  `interpolate_env_with_fallback`, `GatewayConfig::load_with_fallback`,
  `GatewayConfig::parse_with_fallback` and `FileRouteProvider::allowing_unset`
  are new. Existing entry points are unchanged and keep failing on an unset
  variable.
- `ResolvedConfig` gains `placeheld_env`.

### Project

- Copyright is declared: ThinkGrid Labs, in a new `NOTICE` file and in the
  package `authors`. The LICENSE text stays verbatim — its appendix is a
  template to copy into source files, not a field to fill in.
- `cargo deny` now runs in CI and on release. Its licence check had no allow
  list, so it had never passed; every licence in the tree is now enumerated and
  anything new fails the build.

## 0.1.2

- DNS failure on an upstream is a `502` rather than a panicked worker.
- Program name derived from `argv[0]`.

## 0.1.1

- Hardened auth bindings, cache isolation, metrics and upstream handling.

## 0.1.0

- Initial release: identity-aware HTTP gateway on Pingora.
