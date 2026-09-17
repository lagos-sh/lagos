# Route defaults

Use `defaults:` in `gateway.yml` to share `methods`, `retry`, and `rate_limit`
across routes. No Rust code or extra project files are needed. Auth tiers,
listener selection, caching, bindings, and extensions remain route decisions.

```yaml
defaults:
  methods: [GET]
  retry: {attempts: 2}
  rate_limit: {requests: 100, interval: 60s, key: ip}

upstreams:
  catalog: http://catalog:8080
  events: http://events:8080

routes:
  public:
    - id: catalog
      prefix: /catalog
      upstream: catalog
    - id: webhook
      prefix: /webhook
      upstream: events
      methods: [POST]
      retry: null
      rate_limit: null
```

The same two-file setup is available in
[`examples/route-defaults/`](../examples/route-defaults/).

The catalog inherits all three policies. The webhook accepts POST and disables
retries and rate limiting. Policies apply to every route group, including
machine routes on the internal listener. Rate-limit counters are independent
for each route and gateway process; inheritance does not create a shared quota.
Retries still follow Lagos's existing idempotency rules. Disabling the inherited
retry policy preserves existing DNS failover and Pingora recovery for stale
keepalive connections; it does not switch off those built-in behaviors.

| Route input | `retry` and `rate_limit` | `methods` |
|---|---|---|
| Omitted | Inherit the global policy; disabled if none is configured | Inherit the global list; allow any if none is configured |
| `null` | Disable the policy explicitly | Invalid; use `[]` |
| Mapping | Replace the entire policy | Invalid |
| List | Invalid | Replace the list; `[]` allows any method |

Replacement mappings must include their required fields. For example, a route
with `retry: {attempts: 1}` uses the built-in `non_idempotent: false`, even if
its global default sets that flag to true. `rate_limit: {requests: 5}` uses the
built-in 60-second interval and IP key. There is no recursive merge. Invalid
replacements, unknown fields, and a zero-request limit fail validation.
At the global level, omitting a policy or setting `retry`/`rate_limit` to `null`
leaves that policy disabled; `methods: null` is invalid there too.

Run `lagos validate gateway.yml` after editing. Editor schemas describe these
input forms. `lagos routes`, `lagos explain`, and `lagos config --effective`
report each effective policy's origin: `route`, `global defaults`, or `built-in`.
An explicit null or empty list has a `route` origin. Effective output keeps
interpolated defaults redacted, including when they are inherited by literal
external routes; the raw defaults block is hidden. `lagos test` checks matching
against the same resolved table. `lagos diff old.yml new.yml` reports effective
policy changes on inheriting routes, including changes made only to defaults.

## External route files and reloads

Keep defaults in the main document:

```yaml
defaults:
  methods: [GET]
  rate_limit: {requests: 100}
upstreams:
  catalog: http://catalog:8080
routes:
  file: routes.yml
  reload: 2s
```

The separate `routes.yml` contains route groups only:

```yaml
public:
  - prefix: /catalog
    upstream: catalog
  - prefix: /webhook
    upstream: catalog
    methods: [POST]
    rate_limit: null
```

Both inline routes and external files resolve through the same policy rules.
Restart the gateway after changing top-level defaults; they are captured at
startup. Edits to route policies in an already reloadable route file retain
normal reload behavior. Every reload resolves those routes against the captured
defaults and validates the complete table before publishing it. A malformed or
invalid replacement keeps the last valid table serving. Successful reloads
replace route limiters and reset their counters as before.

Existing configurations without `defaults:` retain their behavior. Defaults are
optional; the minimal two-file starter does not need them.
