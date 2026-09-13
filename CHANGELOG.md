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

## 0.1.2

- DNS failure on an upstream is a `502` rather than a panicked worker.
- Program name derived from `argv[0]`.

## 0.1.1

- Hardened auth bindings, cache isolation, metrics and upstream handling.

## 0.1.0

- Initial release: identity-aware HTTP gateway on Pingora.
