# Building a gateway with custom extensions

This convention is in the unreleased 0.1.4 work. The versioned builder image
will become pullable when that release is published.

Most gateways need only `Dockerfile` and `gateway.yml`. When a policy must run
application code, use the optional [extension example](../examples/extension/):

```text
myapp/
├── Dockerfile
├── gateway.yml
└── ext/
    ├── Cargo.toml
    └── src/lib.rs
```

Generate it with `lagos init --docker --extensions`, or copy the example. The
regular two-file starter remains the default. Add any extra Rust dependencies
to `ext/Cargo.toml`; you do not need a root Cargo workspace or a `main.rs`.

## When to use `ext/`

Use an extension when a request decision needs application-specific code or a
live lookup that the verified token and `gateway.yml` cannot provide:

| Use case | What the extension does | Use YAML when |
|---|---|---|
| Merchant or tenant profile lookup | Fetches the caller's current company from an application service, rejects an unverified assignment, and sets trusted upstream headers | The verified token already carries the company claim; use `identity.claims` |
| Branch or account selection | Checks a client-selected branch against the caller's allowed branches before emitting a privileged header | The allowed value is already a single verified claim; use a route `bind` |
| Live entitlement check | Calls a membership or permissions service and rejects access when the entitlement is absent or cannot be verified | Authentication tier and existing token claims fully express the rule |
| Application-specific request context | Builds several related headers from verified identity and a business rule that cannot be expressed as direct claim mapping | Headers are direct claim copies or constants; use `identity.claims` and `inject.headers` |

Petsocare provides three concrete examples:

- **POS cashier context:** A client sends `x-pos-branch-id: 12` with a POS
  request. The extension looks up the verified cashier's company and allowed
  branches, rejects branch 12 if it is not assigned to that cashier, and only
  then emits trusted `x-company-id`, `x-branch-id` and permission headers.
- **Merchant order stream:** A vendor requests
  `/realtime/events/orders?merchantId=42`. The extension compares `42` with
  the vendor's verified company from `legacy-service`; a mismatch is rejected
  before the upstream can stream another merchant's orders.
- **Bookings actor context:** The extension constructs headers for the
  verified caller and merchant. For pexperts, a known independent worker,
  a known employer, and an unknown employer remain three distinct states;
  an unknown employer is never reported as independent.

These policies consult `legacy-service` because the current token does not
carry all the company and branch information they need. They belong in the
application's `ext/`, while Lagos keeps reusable routing and token
verification. An extension receives the canonical request path, method,
query, verified identity and client headers, and may reject the request or
change the upstream header plan. It does **not** inspect or rewrite request
and response bodies. Treat extension code as privileged gateway policy.

Keep network lookups bounded by a timeout and cache only answers whose freshness
is acceptable for the policy. If the lookup cannot verify authority, reject
the request instead of forwarding an unverified tenant or permission header.

The Dockerfile pins **both** `ghcr.io/lagos-sh/lagos-builder` and the Lagos
runtime image to the same version. The builder carries the matching
`lagos-core` source, Rust toolchain and system libraries. It compiles `ext/`
into a new `lagos` binary; the final image copies that binary over the stock
one and includes your `gateway.yml`. An `ext/` directory is source code, not a
runtime plugin directory: copying it into the stock image alone has no effect.

```bash
docker build -t my-gateway .
docker run --rm my-gateway validate
```

Run extension unit tests with the same pinned toolchain, without installing
Rust on the host:

```bash
docker run --rm -v "$PWD/ext:/work/ext:ro" \
  ghcr.io/lagos-sh/lagos-builder:0.1.4 lagos-build /work/ext test
```

In `ext/src/lib.rs`, export `NAMES: &[&str]` and
`extensions() -> anyhow::Result<Vec<Arc<dyn Extension>>>`. Each extension's
`name()` must match a name in `NAMES` and a route's `extensions: [...]` entry.
Keep the generated package name `lagos-app-ext` and library name
`lagos_app_ext`; the builder's generated entrypoint imports that library.
Lagos generates the binary entrypoint and calls `extensions()` on `run`, `dev`
and ordinary `validate`. A missing route registration makes startup fail.

`validate --allow-unset`, including the check during `docker build`, compares
route names with `NAMES` **without constructing extensions**. This permits
build-time checking when an extension needs a runtime secret such as `API_KEY`.
The output says that runtime initialization was unchecked. Ordinary `validate`
and `run` still construct extensions and require those secrets; exercise their
behavior with integration tests. The offline `lagos test` command does not
execute extension code.

The builder uses the Lagos source lockfile as a starting point when no
`ext/Cargo.lock` exists. For a reproducible custom dependency graph, build the
builder stage once and copy out the generated lockfile, then commit it:

```bash
docker build --target build -t my-gateway-build .
build_container=$(docker create my-gateway-build)
docker cp "$build_container:/out/Cargo.lock" ext/Cargo.lock
docker rm "$build_container"
```

Subsequent builds enforce `ext/Cargo.lock` with Cargo's `--locked` option. If
you change `ext/Cargo.toml`, move the old lockfile aside, repeat the builder
stage and copy commands above, then remove the backup after the new image
passes its checks.

The extension API is Rust code linked into the process, so a 0.x version bump
may require source changes. Pin the builder and runtime image tags together,
test the custom image, and read [UPGRADING.md](../UPGRADING.md) before changing
the pin. Existing handwritten custom binaries continue to work; adopting this
folder convention is optional.

For Petsocare, the current `pos`, `bookings`, `merchant_sse` and `legacy` modules
can stay application-specific. Adopting this starter would move their module
declarations and constructor list into `ext/src/lib.rs`, add their dependencies
to `ext/Cargo.toml`, and remove the handwritten gateway entrypoint and builder
Docker stages. It would not change the deployed policy by itself.
