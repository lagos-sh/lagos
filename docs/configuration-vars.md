# Environment variable diagnostics

`lagos vars [CONFIG]` is implemented for **unreleased 0.1.4**. It is not
available in the published 0.1.3 image. It runs in the gateway image or in a
locally built CLI, including binaries with custom extensions. It does not
construct extensions, contact services, or start a server.

Run it before filling in all your environment variables:

```bash
lagos vars
lagos vars config/gateway.yml
```

Configuration discovery matches other CLI commands: an explicit path,
`GATEWAY_CONFIG`, then the [conventional locations](../README.md#cli-reference).

For this configuration:

```yaml
upstreams:
  users: ${USERS_URL}
  orders: ${ORDERS_URL:-http://localhost:3001}
routes:
  public: []
```

With neither variable set, the output is:

```text
SOURCE:LINE:COLUMN     VARIABLE     STATE              DEFAULT  REQUIRED
CONFIG:2:10           USERS_URL    required (unset)    no       yes
CONFIG:3:11           ORDERS_URL   defaulted           yes      no
Inventory complete (inline routes).
Values and default text are hidden. This inventory does not validate configuration.
```

The command emits tab-separated rows. `set` means a nonblank environment value
is present; `defaulted` means the declared default would be used; `required
(unset)` means no value or default is available. `REQUIRED` indicates that the
reference has no default, even when its environment value is currently set.
Empty and whitespace-only environment values count as unset, just as they do
at runtime. Control characters in a selected value are reported as `invalid`.
An empty default still counts as a default; `validate` decides whether the
resulting value is suitable for its field.

Every occurrence gets its own row, including repeated names with different
defaults. Line and column are one-based character positions at the opening `$`
in the original file. Comments are ignored; `$${VAR}` is a literal, not a
reference. In YAML block scalar bodies, `#` is content and references are scanned
using the same rules as runtime interpolation.

`CONFIG` identifies the selected gateway file. `routes.file` identifies the
external route file named by that gateway. These logical source labels keep
filenames containing interpolated credentials out of output. Use the reported
line and column in the corresponding file; the command does not guess field
paths from indentation or print arbitrary configuration keys.

## Run inside Docker

For the current unpublished changes, first build an image from the repository:

```bash
docker build -t lagos-local .
```

From your gateway project directory:

```bash
docker run --rm \
  -v "$PWD:/app:ro" -w /app \
  lagos-local vars gateway.yml
```

Pass the variables you want the inventory to check in the container. For
example, if your local `USERS_URL` is already exported:

```bash
docker run --rm \
  -v "$PWD:/app:ro" -w /app \
  -e USERS_URL \
  lagos-local vars gateway.yml
```

After release, use your matching pinned gateway image in place of `lagos-local`.
Mount the directory when using external route files, so paths relative to
`gateway.yml` are also available inside the container.

## Completeness and errors

The inventory scans the gateway and a resolvable `routes.file`, with relative
paths resolved beside the gateway configuration. Missing variables elsewhere
do not stop the inventory. Missing or invalid path variables, unreadable files,
and YAML fragments whose shape prevents identifying `routes.file` produce an
explicit `UNCHECKED` message and `inventory incomplete`.

Path resolution also follows runtime interpolation before YAML decoding. If
that pipeline cannot parse the document, the external source remains unchecked.
Values injected as whole YAML fragments are not recursively inventoried;
references describe the original files. Extension-specific reads of the process
environment outside those files are outside this inventory.

Exit status is zero for a generated inventory, including missing required
variables, invalid values, and unchecked sources. Reading `CONFIG` or malformed
interpolation syntax fails with a nonzero status and a fixed diagnostic naming
the source and line when available. Errors do not quote YAML, defaults,
substituted values, or interpolated filenames.

`Inventory complete` describes file coverage, not a working deployment. Follow
up with `lagos validate` once values are supplied, or `lagos validate --allow-unset`
for the existing build-time structural checks. The inventory reflects the
command's current files and environment, not a running gateway's snapshot.
