# Signing-key outages

By default expired signing keys fail closed. Set `stale_if_error` on an issuer
only when availability during an identity-provider outage justifies delayed
key revocation:

```yaml
auth:
  jwt:
    - issuer: https://auth.example.com
      audience: [my-api]
      stale_if_error: 5m
```

The same field is available in `auth.firebase`. Default `0s` disables stale use.
After expiry, coordinated refresh is attempted first. If retrieval fails,
previously fetched, parsed keys may be used until **original expiry plus the
configured interval**. Failures never move that deadline. Unknown key IDs and
cold-cache outages still fail closed; every accepted token still undergoes
signature, algorithm, issuer, audience and time checks. A successful refresh
replaces the old set, so removed keys are not recovered from older material.

Stale use cannot distinguish a provider outage from emergency endpoint removal
or a malformed provider response. Disable it when emergency revocation must
propagate without an extra grace interval. Normal cache TTL/minimum TTL already
delays observation of rotations; stale policy extends that tradeoff only when
refresh fails. This is public key caching, not token/revocation caching.

`gateway_jwks_total{outcome}` records `refresh_failed`, `stale_used` and
`stale_exhausted` without user IDs, key IDs or issuer URLs as metric labels.
Cancellation releases refresh leadership and wakes waiters; it cannot leave
later token verification waiting forever on an orphaned refresh.
