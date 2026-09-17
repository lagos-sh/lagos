# Explain route selection

`lagos explain --why-not` and `--listener public|internal` are available starting
with **0.1.4**. These options are not in the 0.1.3 image.
The command uses the current files and environment, without starting a server,
constructing extensions, fetching verification keys, or contacting upstreams.
It does not inspect a running gateway's route snapshot.

Start with the request that is failing:

```bash
lagos explain --path /v1/users/42 --method GET \
  --host api.example.com --why-not
```

The default listener is `public`. To examine a service-to-service route:

```bash
lagos explain --config gateway.yml --listener internal \
  --path /v1/users/42 --method GET --why-not
```

Listener selection chooses the same route partition as runtime. Public,
optional, and authenticated routes belong to the public listener; machine
routes belong to the internal listener. Authentication tier is derived from
the route's group and is not a request selector. If `server.internal_listen`
is absent, an internal explanation reports `listener unavailable`, rather
than inventing a response from a nonexistent socket.

## Read the explanation

Lagos checks the configured mounts in longest-match order, canonicalizes the
remaining path, applies that listener's deny rules, and uses the runtime's
prefix, host, and method predicates to select a route. Query strings do not
participate in path matching. The exact configured health path is answered
locally before mount and route checks, just as it is at runtime.

If route selection fails, `--why-not` lists every enabled route whose canonical
prefix matches on a segment boundary. It includes candidates from the other
listener so a misplaced request is visible. Each candidate reports all relevant
constraints, for example:

```text
Prefix candidates

  users-read  /users  (group: public): host mismatch; requires api.example.com; method mismatch; allows GET
  users-internal  /users  (group: machine): belongs to internal listener
```

A missing Host header is distinguished from a host mismatch. Host matching
ignores case and the incoming port; a wildcard requires a subdomain. An empty
method list allows every method and never produces a method-mismatch reason.
A public deny rule takes precedence over an otherwise eligible route; its
candidates are reported as blocked before route matching. That deny rule does
not block the internal machine table.

If no enabled prefix matches, the command says so. Disabled routes are omitted,
matching their absence from the runtime table. If a mount does not match or the
path is unsafe, explanation stops at that failure: there is no canonical
route path to evaluate. When a route is selected, `--why-not` adds no refusal
candidates and the existing route-policy explanation continues.

## What remains unchecked

A selected route is not a verified or proxied request. The output explicitly
marks credentials, client-header/body checks, rate limits, ownership checks,
extension execution, cache behavior, CORS preflight handling, and upstream
availability as unchecked. Listener binding is not attempted. The command
shows configured policies, including the injection header names for the chosen
listener, with injected values redacted.

The `404` results describe mount/path/deny/allowlist selection. Other runtime
checks can affect the final response. In particular, an OPTIONS request with
valid CORS preflight headers can receive a local response; `explain` does not
accept or evaluate those headers. No rate-limit counters are consumed and no
credential supplied to a running gateway is verified by this command.

The command's exit status is zero when an explanation is produced, including
a routing refusal or unavailable listener. Invalid configuration and invalid
CLI arguments fail with a nonzero status. This is an offline CLI tool; Lagos
adds no HTTP route-inventory or refusal-details endpoint.

## Use the Docker CLI

Use the published runtime image from your gateway project directory:

```bash
docker run --rm \
  -v "$PWD:/app:ro" -w /app \
  ghcr.io/lagos-sh/lagos:0.1.4 explain --config gateway.yml \
  --path /v1/users/42 --host api.example.com --why-not
```

Pass the environment variables needed to load your configuration with Docker's
`-e VARIABLE` options. `lagos vars` can inventory those dependencies first;
see [variable diagnostics](configuration-vars.md). Mount the configuration
directory to make relative external route files available. Use the pinned
gateway image matching your deployment, including your custom application
image if you use extensions.
