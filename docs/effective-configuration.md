# Redacted effective configuration

`lagos config --effective [CONFIG]` is available starting with **0.1.4**.
It produces a JSON diagnostic view of configuration resolved from this
invocation's files and environment. It does not inspect a serving gateway's
in-memory snapshot, even when run inside the same pod.

```bash
lagos config --effective
lagos config --effective config/gateway.yml
```

Configuration discovery matches the other CLI commands. Required variables must
be supplied and the configuration must parse and pass configuration resolution
and route-table validation. Use [variable diagnostics](configuration-vars.md)
to inventory missing variables first.

The command reads each source file once. Relative `routes.file` paths are
resolved beside the gateway file. Resolution, provenance, and redaction use
those captured bytes. Different files are read separately, so this is not an
atomic snapshot across gateway and route files.

## Read the view

The output begins with explicit scope and safety metadata:

```json
{
  "diagnostic": true,
  "suitable_for_deployment": false,
  "is_running_snapshot": false
}
```

The `configuration` object contains an explicit projection of the resolved
settings. Reviewed typed controls such as timeouts, body/token limits, thread
count, DNS limits, cache policy, retries, rate-limit policy, and route flags can
be shown. Fields carry a `value`, an `origin`, and a `redacted` flag, for example:

```json
{
  "value": "30s",
  "origin": "built-in",
  "redacted": false
}
```

Origins such as `CONFIG.server.threads` identify a known configuration location.
`built-in` identifies an input field that was absent and used its default.
Nested policy objects can include defaults inside a configured object.

Route and upstream entries have synthetic references such as `route-1` and
`upstream-1`. These preserve associations without exposing user-supplied names.
Routes are emitted in runtime table order, with normalized methods, the derived
authentication group, and the appropriate listener. Disabled routes are absent
from that table. Route origins identify the source group, for example
`CONFIG.routes.public` or `routes.file.authenticated`; they do not claim an
individual field was explicitly supplied.

## Redaction policy

The view defaults to hiding unclassified data. It never serializes the runtime
configuration or relies on its Debug implementation to suppress secrets.

- Credentials, identity-token settings, authentication data, injected headers,
  ownership bindings, and extension names/settings are hidden.
- URLs, including their usernames, passwords, hosts, paths and query strings,
  are hidden in full. Health-check paths and arbitrary header names are hidden.
- User-defined identifiers, route prefixes, hosts, mounts, custom method names,
  and other unclassified strings are hidden. Standard HTTP method names and
  reviewed fixed enums can be shown.
- Source paths are retained as redacted fields under `sources`. Logical labels
  `CONFIG` and `routes.file` identify the selected inputs without exposing
  credentials embedded in a filename or interpolated path.
- Interpolated settings are hidden, whether they used an environment value or a
  declared default. This applies to numbers, booleans, durations, and whole YAML
  structures, as well as strings.

Provenance is deliberately conservative for route groups and upstream policies:
any interpolation in a group hides that group's projected values. Unknown
origins, interpolated keys, and fields introduced by flow-mapping substitutions
are hidden rather than reported as literal input or built-in defaults.
Individual hidden components inside an otherwise visible typed policy also
use `<redacted>`.

This view is **unsuitable for deployment**. It omits or hides settings needed to
serve traffic, and its metadata makes it a different document from gateway YAML.
There is no raw or unredacted switch. Keep your source configuration as the
input to `run` and `validate`.

## Checked and unchecked work

`checked` records input parsing, configuration resolution, and route-table
validation. The command constructs no extensions and makes no upstream or
verification-key requests. Extension registration and configuration introspection
are explicitly unchecked, including in custom binaries. Credential verification,
listener binding, DNS reachability, upstream availability, and running rate-limit,
cache, and service state also remain unchecked.

An invalid configuration, missing required variable, or unreadable source fails
with a nonzero exit status and no partial JSON output. Errors use fixed source
labels and reasons; they do not quote paths, YAML, parser payloads, defaults, or
substituted values. Safe interpolation diagnostics retain the source line.
A successfully produced diagnostic view exits with status zero.

This redaction contract applies to `config --effective`; other commands have
their own output contracts. It does not change configuration keys or request
handling.

## Docker usage

Use the published runtime image from your gateway project directory, passing
the variables required by your files:

```bash
docker run --rm \
  -v "$PWD:/app:ro" -w /app \
  -e USERS_URL \
  ghcr.io/lagos-sh/lagos:0.1.4 config --effective gateway.yml
```

Mount the directory so external route files are available beside the gateway
file. Use the pinned gateway image matching your deployment, including your
custom application image if you use extensions. This command is not available
in the 0.1.3 image.

Effective route policies include `policy_origin` (`route`, `global defaults`, or
`built-in`). Inherited policies use the corresponding `CONFIG.defaults` source
for redaction, with the route-group guard still applied. The raw defaults block
is hidden; see [route defaults](route-defaults.md).
