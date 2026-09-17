# Configuration in your editor

Lagos provides JSON Schema for `gateway.yml` and standalone route files. Editors
with YAML language-server support can use these schemas for completion, field
descriptions, and feedback on unknown fields and incorrect input shapes.

Schema commands are part of the unreleased 0.1.4 CLI and its upcoming Docker
image. The published 0.1.3 image does not provide them. Until release, build a
local image from this repository:

```bash
docker build -t lagos-local .
docker run --rm lagos-local schema > gateway.schema.json
docker run --rm lagos-local schema --routes > routes.schema.json
```

These commands write JSON to your host terminal through Docker. They do not need
a configuration mount, environment variables, an upstream connection, or extension
initialization. Native CLI users can run `lagos schema` and
`lagos schema --routes` with the same redirections.

Add this comment at the top of a gateway configuration beside the exported file:

```yaml
# yaml-language-server: $schema=./gateway.schema.json
```

For a standalone route file, use `./routes.schema.json` instead. Paths in editor
comments are relative to the YAML file, so adjust them when files are in different
directories. Schema files are optional editor assets and do not need to be copied
into your gateway image. A standard deployment still needs only `Dockerfile` and
`gateway.yml`.

To generate a starter with a local schema comment, use:

```bash
lagos schema > gateway.schema.json
lagos init --docker --schema ./gateway.schema.json
```

The equivalent Docker command needs a writable mount and a working directory:

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" -w /work lagos-local \
  init --docker --schema ./gateway.schema.json
```

Local/source builds omit remote schema comments unless you supply `--schema`.
Official version-tag image builds generate a comment pointing to
`schemas/gateway.schema.json` in the matching Git tag, and pin the starter's Docker
image to that version. Release verification checks the committed schema against
the compiled types and checks the versioned URL before publishing images. The
remote comment applies only to a version whose release artifacts exist; it is not
generated automatically for unpublished local versions.

When upgrading an image, also update its schema reference, or export a new local
schema from that image. Prefer the complete version tag over a floating branch so
the editor describes the configuration your gateway accepts. `--schema PATH_OR_URL`
can explicitly select a local file or a published URL.

Schemas describe YAML input forms, including upstream URL/pool shorthand, weighted
targets, claim mappings, host strings/lists, size strings/numbers, duration strings,
and interpolation in typed fields. Interpolation support permits variables before
their values are available; it does not validate what those variables will become.
Duration parsing, route conflicts, cross-field policy rules, extension registration,
DNS, credentials, and service availability still need the relevant Lagos checks.

Run `lagos validate` with your deployment environment before serving traffic.
`validate --allow-unset` reports unchecked variables during a build; it cannot
prove those values will work at runtime. Editor validation never starts Lagos or
fetches runtime services.

To refresh the repository's committed schema artifacts after changing input types:

```bash
cargo run --quiet --locked -p lagos -- schema > schemas/gateway.schema.json
cargo run --quiet --locked -p lagos -- schema --routes > schemas/routes.schema.json
cargo test -p lagos-core config::schema::tests
```

The generated schemas use JSON Schema Draft 7 for editor compatibility. They are
derived from input types, with explicit overrides for custom deserializers.
Runtime-derived route fields are omitted. Tests cover accepted examples, invalid
input shapes, typed interpolation, and committed-artifact drift.
