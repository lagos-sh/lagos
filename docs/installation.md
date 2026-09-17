# Install the Lagos CLI

The stock `lagos` executable includes gateway serving and all CLI commands.
Installing a release binary requires no Rust, Cargo, Git, or Docker. Your
backend services can use any language. Docker remains an alternative, and
custom extensions remain optional.

**Availability:** standalone downloads are prepared for unreleased 0.1.4.
The release URLs below become usable after that version is published. Earlier
image releases do not provide these native downloads. Until then, use Docker
or [build from source](../README.md#install-from-source).

## Linux and macOS

Download the installer from the latest stable GitHub Release and run it:

```sh
curl -fsSL https://github.com/lagos-sh/lagos/releases/latest/download/install.sh -o install-lagos.sh
sh install-lagos.sh
export PATH="$HOME/.local/bin:$PATH"
lagos --version
```

The installer detects the operating system and CPU architecture, downloads
its matching archive and `SHA256SUMS`, verifies the archive, and checks the
binary's version before installing it. Its default destination is
`$HOME/.local/bin/lagos`. It does not use sudo or edit shell profiles. If that
directory is not already on your PATH, add the `export` line to your shell's
startup file to retain it in future terminals.

Pin a version, including a prerelease, or choose another installation directory:

```sh
sh install-lagos.sh --version 0.1.4
sh install-lagos.sh --version 0.1.4-rc.1 --bin-dir "$HOME/bin"
```

You can also pin the installer itself to a release:

```sh
curl -fsSL https://github.com/lagos-sh/lagos/releases/download/v0.1.4/install.sh -o install-lagos.sh
sh install-lagos.sh --version 0.1.4
```

Re-running the installer upgrades or replaces the executable after verification.
Failed downloads, checksum failures, and incompatible binaries leave the
existing executable intact. `latest` selects the latest stable GitHub Release;
prereleases require an explicit version. Checksums detect download corruption;
both the archive and manifest are obtained from the same release over HTTPS.

| System | CPU | Release target |
|---|---|---|
| Linux | Intel/AMD 64-bit | `x86_64-unknown-linux-musl` |
| Linux | ARM64 | `aarch64-unknown-linux-musl` |
| macOS 14 or later | Intel | `x86_64-apple-darwin` |
| macOS 14 or later | Apple silicon | `aarch64-apple-darwin` |

Linux binaries are statically linked with musl and do not require a particular
glibc installation. macOS binaries use Apple's system libraries. The installer
requires `curl`, `tar`, and either `sha256sum` or `shasum`, alongside normal shell
utilities. Windows native binaries and a PowerShell installer are outside this
release's scope; use Docker or the Linux installer inside WSL.

## Manual download

Open [GitHub Releases](https://github.com/lagos-sh/lagos/releases), choose a
version, and download its matching `lagos-VERSION-TARGET.tar.gz` plus
`SHA256SUMS`. For example, on an Intel/AMD Linux machine:

```sh
version=0.1.4
archive="lagos-$version-x86_64-unknown-linux-musl.tar.gz"
base="https://github.com/lagos-sh/lagos/releases/download/v$version"
curl -fSL "$base/$archive" -o "$archive"
curl -fSL "$base/SHA256SUMS" -o SHA256SUMS
grep "  $archive$" SHA256SUMS | sha256sum --check
mkdir -p lagos-release
tar -xzf "$archive" -C lagos-release
mkdir -p "$HOME/.local/bin"
install -m 755 lagos-release/lagos "$HOME/.local/bin/lagos"
export PATH="$HOME/.local/bin:$PATH"
lagos --version
```

On macOS, select the Darwin target and use `shasum -a 256 --check` in place of
`sha256sum --check`. Keep the included `LICENSE` and `NOTICE` when redistributing
an archive or executable.

## First use

```sh
mkdir my-gateway
cd my-gateway
lagos init --docker
lagos validate gateway.yml
```

That produces root-level `Dockerfile` and `gateway.yml`; installed CLI users
can run diagnostics directly in their terminal. Serving can still use the
Docker image, or run natively with `lagos run gateway.yml`. Plain `lagos init`
generates a native-use YAML starter without a Dockerfile. Release binaries use
the same version-matched editor schema convention as official release images.

For custom functionality, `lagos init --docker --extensions` adds the optional
`ext/` starter. The extension builder image contains the Rust toolchain, so
users can compile it through Docker without installing Rust locally. Writing
those extensions still uses Rust; see [extensions](extensions.md).

## Release verification

CI builds all four native targets on matching native runners. It verifies
static Linux linkage or macOS system linkage, exercises version/schema output,
scaffolding, validation, and a loopback proxy request, and tests the installer
against local fixtures. Packages include the binary, `LICENSE`, and `NOTICE`.

On version tags, schema references are enabled only after version and schema
checks pass. After native checks and Docker image smoke checks succeed, the
workflow assembles all four archives, the installer, and `SHA256SUMS`, uploads
them to a draft GitHub Release, and publishes it. No native assets are attached
to existing published releases. These workflows are release preparation;
editing them does not publish 0.1.4.
