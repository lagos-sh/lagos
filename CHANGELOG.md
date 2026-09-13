# Changelog

Behaviour changes and the config needed to preserve existing behaviour are in
[UPGRADING.md](UPGRADING.md).

## 0.1.3 — request-path hardening

### Security

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
- Fetched JWKS / certificate bodies are capped at 1 MiB.
- A verified token whose `sub`, `iss` or mapped claim cannot be a header value is
  refused before any header is built.

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

## 0.1.2

- DNS failure on an upstream is a `502` rather than a panicked worker.
- Program name derived from `argv[0]`.

## 0.1.1

- Hardened auth bindings, cache isolation, metrics and upstream handling.

## 0.1.0

- Initial release: identity-aware HTTP gateway on Pingora.
