# Deploying a two-file Lagos gateway

The [minimal example](../examples/minimal/) is a complete image build:
`Dockerfile` copies `gateway.yml` into the stock Lagos image and validates its
structure. Keep both files at the application root. Each config change makes a
new image; deploy that image by an immutable version or digest. Restarting an
unchanged image does not pick up a file edited on your laptop.

This setup uses `ghcr.io/lagos-sh/lagos:0.1.4`, the gateway runtime image.
`ghcr.io/lagos-sh/lagos-builder:0.1.4` is needed only to compile or test optional
custom `ext/` policies. An extension build uses both images as build stages,
then produces one application image to deploy. See
[the image comparison](../README.md#which-docker-image-should-i-use) and
[building with extensions](extensions.md).

## Docker Compose

Add Lagos to the Compose project that already runs your application. Given a
service named `users` listening on port 3000, this is the gateway service:

```yaml
services:
  gateway:
    build: .
    ports:
      - "8080:8080"
    environment:
      USERS_URL: http://users:3000
```

Compose gives the service name a network address. `USERS_URL` overrides the
starter's `host.docker.internal` default, which is intended only for a service
running directly on your development machine. Check
`http://localhost:8080/health`, then a configured route such as `/users`.

If `gateway.yml` uses `${API_KEY}` or another required variable, supply it as
an environment variable or secret to the gateway container. Keep secret values
out of `gateway.yml` and the Dockerfile. A build-time
`validate --allow-unset` cannot check those values; `run` refuses to start when
one is absent. To check the exact runtime environment before serving traffic:

```bash
docker compose run --rm gateway validate
```

## Kubernetes or an existing ingress

Use the same built image in a Deployment. Give it an HTTP readiness probe at
`/health`, and point a Service at container port 8080. Put your existing TLS
ingress or load balancer in front of that Service. Lagos does not terminate
public TLS or manage certificates.

Pass upstream addresses and required secrets as environment variables in the
Deployment. For example, `USERS_URL` can be
`http://users.default.svc.cluster.local:3000`, while a required `${API_KEY}`
should come from a Kubernetes Secret. Check that every required variable named
in `gateway.yml` has a source in the Deployment before rollout; the image
build can only validate the structure when production values are unset.

If you add `server.internal_listen` for machine routes, give it a separate
internal Service and restrict network access to that port. Keep the metrics
listener private as well. Lagos discards arriving `X-Forwarded-For` by default.
If upstreams or IP rate limits need the real client address behind your ingress,
set `forward.trusted_proxies` to the exact number of trusted HTTP hops and
`forward.trusted_proxy_ips` to their source CIDRs. See
[Client addresses and trusted proxies](../README.md#client-addresses-and-trusted-proxies)
before changing the safe default.

For a separate route file, add `routes: { file: routes.yml }` to `gateway.yml`
and copy `routes.yml` beside it in the image. The main config needs a new image
and process restart after a change. A route file hot-reloads only if it is
mounted as a changing file and `routes.reload` is configured; a file baked into
an immutable image changes only when a new image is deployed.

If a route needs application-specific code or a live authorization lookup,
use the optional [`ext/` convention](extensions.md). Its builder image compiles
the extension into the gateway binary; the two-file stock image cannot load
Rust source at runtime.
