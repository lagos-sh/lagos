# Request resource budgets

Unreleased source supports an optional absolute exchange lifetime:

```yaml
timeouts:
  request_total: 60s # omitted/null preserves existing long-lived exchanges
```

One deadline starts when Pingora dispatches the HTTP session and covers header
parsing, authentication, extension hooks, DNS, retries, request body and streamed
response. Ongoing byte progress does not reset it. Expiry drops the exchange and
closes the downstream connection. It does **not** promise a synthetic 504:
authentication or header parsing may not have produced a response, while a
stream may already have sent its status. `gateway_request_deadlines_total`
counts these closures separately from upstream timeout errors. RAII releases
route concurrency, cache fills and JWKS refresh leadership on cancellation.
Native blocking code still requires cooperative execution; Tokio cannot preempt
it. The deadline does not cover work before HTTP dispatch or separately spawned
extension tasks.

This budget applies to every route on the listener, including SSE and uploads.
Use a lifetime that accommodates the longest legitimate stream/upload, or omit
it for a dedicated streaming deployment. Existing `sse` and `upload` timeouts
are per-I/O budgets; they do not override `request_total`. No buffering is added.
The default remains null to preserve existing SSE behavior.

Other controls already enforced:

| Control | Scope |
| --- | --- |
| `timeouts.downstream_read` | Absolute header-read deadline, then maximum body-read gap |
| `timeouts.downstream_write` | One downstream write may stall only this long |
| `timeouts.downstream_drain` | Bound discarding a refused request body |
| `limits.max_body` | Declared and streamed request-body bytes |
| `limits.max_token` | Token bytes before parsing/signature work |
| `limits.connections_per_ip` | Accept rate from socket peer; not a live connection count |
| `limits.keepalive_requests` | Requests before a keepalive connection is retired |
| Route `concurrency` | Requests in upstream/response transfer, per process |
| `limits.extension_inflight` | Executing policy chains, shared across registry/listener clones |

When `limits.min_send_rate` is set, Pingora's rate-derived write timeout takes
precedence over ordinary downstream write/SSE write settings. Configure it with
the expected stream write sizes and slow-client behavior in mind.

## Header and connection protections at ingress

Pingora 0.9 already bounds HTTP/1 parsing to 256 fields and roughly 1 MiB of
header data (its byte threshold can overshoot by a read). Lagos does not expose
an earlier configurable parser byte ceiling. A check after parsing would not
bound parser allocation, so no such protection is claimed here. Configure and
test a smaller maximum header budget, header deadline and global live-connection
ceiling at the ingress that terminates public connections. Test both one large
field and many small fields, stalled headers and continuously progressing
streams; confirm oversized input is refused before reaching Lagos.

The accept rate and route caps do not replace an ingress connection ceiling.
Aggregate memory from concurrent cache fills also needs separate load testing;
a per-object/store cap alone does not bound every outstanding fill buffer.
