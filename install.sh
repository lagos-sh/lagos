#!/bin/sh
# Installs a stock Lagos release binary; no Rust, Cargo or sudo required.
set -eu

fail() { printf 'lagos installer: %s\n' "$*" >&2; exit 1; }
usage() {
    cat <<'EOF'
Usage: sh install.sh [--version VERSION] [--bin-dir DIRECTORY]

Defaults: latest stable release, $HOME/.local/bin
Supports Linux and macOS on x86_64 and ARM64.
EOF
}

lagos_tmp=
lagos_staged=
cleanup() {
    if [ -n "$lagos_staged" ]; then rm -f "$lagos_staged"; fi
    if [ -n "$lagos_tmp" ]; then rm -rf "$lagos_tmp"; fi
}
trap cleanup 0
trap 'exit 1' HUP INT TERM

main() {
    lagos_version=latest
    lagos_bin_dir=${HOME:?HOME is required}/.local/bin
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --version)
                [ "$#" -ge 2 ] || fail '--version requires a value'
                lagos_version=$2; shift 2 ;;
            --bin-dir)
                [ "$#" -ge 2 ] || fail '--bin-dir requires a value'
                lagos_bin_dir=$2; shift 2 ;;
            --help|-h) usage; return ;;
            *) fail "unknown option: $1" ;;
        esac
    done
    [ -n "$lagos_bin_dir" ] || fail '--bin-dir cannot be empty'
    case "$lagos_bin_dir" in /*) ;; *) lagos_bin_dir=$PWD/$lagos_bin_dir ;; esac
    for lagos_tool in curl tar awk grep uname mktemp chmod cp mv mkdir; do
        command -v "$lagos_tool" >/dev/null 2>&1 || fail "required command not found: $lagos_tool"
    done
    if command -v sha256sum >/dev/null 2>&1; then
        lagos_hash_tool=sha256sum
    elif command -v shasum >/dev/null 2>&1; then
        lagos_hash_tool=shasum
    else
        fail 'SHA-256 verification requires sha256sum or shasum'
    fi
    case "$(uname -s)" in
        Linux) lagos_os=unknown-linux-musl ;;
        Darwin)
            lagos_os=apple-darwin
            command -v sw_vers >/dev/null 2>&1 || fail 'cannot determine the macOS version'
            lagos_macos=$(sw_vers -productVersion)
            lagos_macos_major=${lagos_macos%%.*}
            case "$lagos_macos_major" in ''|*[!0-9]*) fail 'cannot determine the macOS version' ;; esac
            [ "$lagos_macos_major" -ge 14 ] || fail 'macOS 14 or later is required; use Docker on older systems' ;;
        *) fail 'supported systems are Linux and macOS; use Docker or WSL on Windows' ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64) lagos_arch=x86_64 ;;
        aarch64|arm64) lagos_arch=aarch64 ;;
        *) fail 'supported architectures are x86_64 and ARM64' ;;
    esac
    lagos_repo=https://github.com/lagos-sh/lagos
    if [ "$lagos_version" = latest ]; then
        lagos_latest=$(curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --fail --silent --show-error --location --connect-timeout 10 --max-time 120 \
            --output /dev/null --write-out '%{url_effective}' "$lagos_repo/releases/latest") \
            || fail 'cannot find the latest release; standalone downloads begin with 0.1.4'
        case "$lagos_latest" in
            "$lagos_repo/releases/tag/v"*) lagos_version=${lagos_latest##*/} ;;
            *) fail 'latest release did not resolve to a version tag' ;;
        esac
    fi
    lagos_version=${lagos_version#v}
    case "$lagos_version" in ''|*[!0-9A-Za-z.-]*) fail 'invalid version; use e.g. 0.1.4 or 0.1.4-rc.1' ;; esac
    printf '%s\n' "$lagos_version" | LC_ALL=C grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$' \
        || fail 'invalid version; use e.g. 0.1.4 or 0.1.4-rc.1'
    lagos_target=$lagos_arch-$lagos_os
    lagos_archive=lagos-$lagos_version-$lagos_target.tar.gz
    lagos_base=$lagos_repo/releases/download/v$lagos_version
    umask 077
    lagos_tmp=$(mktemp -d)
    for lagos_file in "$lagos_archive" SHA256SUMS; do
        curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
            --fail --silent --show-error --location --connect-timeout 10 --max-time 120 \
            --output "$lagos_tmp/$lagos_file" "$lagos_base/$lagos_file" \
            || fail "cannot download $lagos_file; check that v$lagos_version has standalone assets"
    done
    lagos_expected=$(awk -v name="$lagos_archive" '$2 == name { print $1 }' "$lagos_tmp/SHA256SUMS")
    case "$lagos_expected" in ''|*[!0-9a-f]*) fail 'invalid or missing archive checksum' ;; esac
    [ "${#lagos_expected}" -eq 64 ] || fail 'invalid or duplicate archive checksum'
    if [ "$lagos_hash_tool" = sha256sum ]; then
        lagos_actual=$(sha256sum "$lagos_tmp/$lagos_archive" | awk '{print $1}')
    else
        lagos_actual=$(shasum -a 256 "$lagos_tmp/$lagos_archive" | awk '{print $1}')
    fi
    [ "$lagos_actual" = "$lagos_expected" ] || fail 'archive checksum mismatch; installation cancelled'
    # Stream just the executable; archive entries cannot write outside scratch.
    tar -xOzf "$lagos_tmp/$lagos_archive" lagos > "$lagos_tmp/lagos" \
        || fail 'release archive does not contain lagos'
    chmod 755 "$lagos_tmp/lagos"
    lagos_reported=$("$lagos_tmp/lagos" --version) || fail 'binary cannot run on this machine'
    [ "$lagos_reported" = "lagos $lagos_version" ] || fail 'binary version does not match the requested release'
    [ ! -d "$lagos_bin_dir/lagos" ] || fail 'installation destination is a directory'
    mkdir -p "$lagos_bin_dir"
    lagos_staged=$(mktemp "$lagos_bin_dir/.lagos-install.XXXXXX")
    cp "$lagos_tmp/lagos" "$lagos_staged"
    chmod 755 "$lagos_staged"
    mv -f "$lagos_staged" "$lagos_bin_dir/lagos"
    lagos_staged=
    printf 'Installed lagos %s to %s/lagos\n' "$lagos_version" "$lagos_bin_dir"
    case ":${PATH:-}:" in
        *":$lagos_bin_dir:"*) ;;
        *) printf 'Add this directory to PATH: %s\n' "$lagos_bin_dir" ;;
    esac
}

main "$@"
