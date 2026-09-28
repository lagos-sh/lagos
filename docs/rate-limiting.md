# Rate limiting

Limits are per route. A request over the limit gets `429` with `Retry-After`.
Local and approximate shared counters use a sliding-window estimate: the
previous interval weighted by how much of it is still in view. Exact shared
limits use the backend's authoritative sliding window. A burst either side
of a window boundary cannot double the quota.

```yaml
routes:
  authenticated:
    - prefix: /search
      upstream: search
      rate_limit:
        requests: 100
        interval: 1m
        key: identity
```

Keys are `ip`, `identity`, `route`, or `header.<name>`. A key that cannot be
determined for a request means that request is not limited — lumping every
anonymous caller into one bucket would throttle them collectively, which is
worse than not limiting them. Pick a key that is present on every request that
must be covered.

Keys are scoped per route, so a quota spent on `/search` is not spent on
`/orders`.

## Choosing a counter

| `counter` | Memory | Accuracy | Scope |
|---|---|---|---|
| `exact` (default) | One counter per key, capped at `max_keys` | No collisions: a `429` is always the caller's own doing | This process |
| `sketch` | Fixed, whatever the key cardinality | Over-counts on collision: one caller can be refused for another's traffic | This process |
| `shared` | One counter per key, plus a cache | Cluster-wide, to within the mode below | Every replica |

`exact` and `sketch` need no cache, no clock sync and no network hop. The cost is
that a limit of 100/min across three replicas admits up to 300/min. For
protecting an upstream from a runaway client that is usually the right trade.

When it is not — when the `429` is a promise to a specific customer, or the
limit is the thing standing between a paid tier and a free one — `shared` makes
the number mean what it says.

## Sharing counters across replicas

```yaml
shared_counters:
  url: recached://cache:6379
  sync: 1s

routes:
  authenticated:
    - prefix: /search
      upstream: search
      rate_limit:
        requests: 100
        interval: 1m
        key: identity
        counter: shared
```

One backend per gateway; routes opt in individually. A `shared_counters` block
that no route uses connects to nothing, which makes it a safe intermediate state
during a rollout.

### Any RESP server

Recached, Redis and Valkey all work. The commands used are `HSETNX`, `HVALS`,
`EXPIRE` and — in `exact` mode only — Recached's `RLCHECK`. Deliberately no
`EVAL`: Recached implements no Lua, so the usual trick of shipping a
sliding-window script would not run against it at all.

`recached://`, `valkey://`, `resp://` and `redis://` are all accepted, each with
a trailing `s` for TLS, so the configuration need not name a product you do not
run. They are aliases for one protocol, not different behaviours.

### Two modes

| `mode` | Request-path cost | Accuracy | Works on |
|---|---|---|---|
| `approximate` (default) | None | Overshoot scales with `replicas x arrival rate x reconciliation period` | Recached, Redis, Valkey |
| `exact` | One round trip per limited request | Exact | Recached only |

**`approximate`** decides locally and reconciles in the background. The local
window admits or refuses with no I/O at all; a background task publishes this
replica's usage on `sync` ticks and reads back what the others have used.
Capped batches rotate across keys. For a stable key set, a full pass takes
roughly `ceil(keys / max_keys_per_sync)` ticks, plus backend latency; retries
can extend that period. Overshoot scales with this effective reconciliation
period, rather than always with one `sync` interval.

Each snapshot carries outstanding usage for both the current and previous
windows. Contributions have immutable IDs stored with `HSETNX`; a lost response
retries the same IDs, so a write that succeeded before a timeout is counted once.
No request waits on the cache.

**`exact`** uses `RLCHECK`, which records an attempt and returns
`[allowed, remaining, retry_after_ms]` in one command. The limit then holds with
no overshoot and no window alignment to reason about. The cost is real and should
be chosen deliberately: every limited request now waits on the cache, and a slow
cache is slow requests.

`RLCHECK` has no Redis or Valkey counterpart and cannot be emulated without
`EVAL`. So the backend is identified at startup, and `mode: exact` pointed at
anything but Recached refuses to boot. Route reloads run the same check before
publishing; a rejected reload keeps the previous routes active.

### When the cache is unreachable

**Traffic continues.** Limits fall back to per-process counting and
`gateway_shared_limit_errors_total` climbs. A cache outage must not become a
gateway outage; that rule is why the connection is lazy, why the sync task never
sits on the request path, and why a failed `RLCHECK` answers from the local
window instead of refusing.

That counter is the one to alert on, because the gateway keeps serving and
nothing else reports that a cluster-wide limit is no longer cluster-wide:

| Metric | Meaning |
|---|---|
| `gateway_shared_limit_errors_total` | Reconciliations or checks the backend could not answer. Non-zero means limits have degraded to per-process |
| `gateway_shared_limit_keys_synced_total` | Keys reconciled. Flat while traffic continues means sync has stopped |

The one exception is `mode: exact` at startup: it cannot be honoured at all
without the backend, so an unreachable cache fails the boot rather than starting
with a limit that never applies.

### Clocks

A shared window is indexed by `unix_time / interval`, because that is the one
thing every replica can compute identically — the local counters anchor each
window at the moment a key was first seen, which is better inside one process and
useless across several.

So this rests on the wall clock. Replicas whose clocks differ by `d` disagree
about where a window boundary falls by `d`, and an NTP step moves the boundary
under them. Neither breaks a limit: a request is always counted into some window
exactly once, and the sliding weight means no boundary is a cliff. It only blurs
which window. Run NTP; skew approaching a full interval is the point at which the
previous-window weighting stops meaning much, and `mode: exact` sidesteps the
question entirely.

### Settings

| Field | Default | Notes |
|---|---|---|
| `url` | — | Required. TLS with a trailing `s` on the scheme. Credentials are redacted in logs, `Debug` output and errors |
| `sync` | `1s` | How often usage is published and read back. The accuracy knob; it buys accuracy with cache traffic, not request latency |
| `prefix` | `lagos:rl:` | Prefix on every key written, so one cache can serve this gateway alongside anything else |
| `timeout` | `250ms` | Budget for one round trip. In `approximate` mode a timeout costs accuracy; in `exact` mode it is the ceiling on how long a request waits |
| `max_keys_per_sync` | `4096` | Keys reconciled per tick, visited in rotation. A full pass takes roughly `ceil(keys / max_keys_per_sync)` ticks, plus backend latency and retries |

These rules are checked at startup and on route reloads:

- `interval` must be at least `1s`. In `exact` mode it must also be a whole
  number of seconds: `RLCHECK` cannot represent fractional windows. Approximate
  mode preserves fractional intervals such as `1.9s`.
- `sync` must be shorter than `interval` in `approximate` mode. Reconciling at
  most once per window would leave the limit shared in name only.

### Memory

Rate-limit keys come from requests, so an unbounded store is a
memory-exhaustion bug. The local store is capped at `max_keys` per route and
entries expire after two intervals — as far back as the estimate can see. Under a
flood of distinct keys the oldest are evicted, which degrades limiting for those
keys rather than the process.

The same cap applies to shared counters. Only requests refresh local idle
timers; background reconciliation does not keep unused keys alive. Cache-side
window hashes carry a TTL of two intervals, rounded up to whole seconds. Each
nonzero publication adds an immutable contribution field, so cache memory grows
with replicas and publications retained within those windows. Shorter sync
periods increase both command traffic and contribution storage.

### Builds

The shipped `lagos` binary and the Docker images include this. A custom gateway
built on `lagos-core` with `default-features = false` needs the `shared-limits`
feature; `counter: shared` in a build without it is a startup error naming the
feature, never a silent downgrade to local counting.

## IP limits behind a proxy

For `key: ip`, set `trusted_proxies` inside the route's `rate_limit` block. `0`
believes nothing in `X-Forwarded-For` and uses the socket peer; `1` uses the last
entry; `n` counts from the right. It must match the chain actually in front of
the gateway — set too high, it reads a client-supplied address and hands out a
fresh quota per forged one. See
[Client addresses and trusted proxies](../README.md#client-addresses-and-trusted-proxies).

## Connection-level limits

`server.connection_limit` is a separate, always-local limiter that runs at accept
time, before the TLS handshake and before a connection costs a task or a file
descriptor. It is never shared: there is nowhere to await a round trip that early,
and a connection flood is exactly the moment a gateway must not be waiting on a
cache to decide anything.
