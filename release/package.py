"""Package a verified native executable and generate release checksums."""
import argparse
import gzip
import hashlib
import pathlib
import re
import tarfile

TARGETS = (
    "x86_64-unknown-linux-musl",
    "aarch64-unknown-linux-musl",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
)
ROOT = pathlib.Path(__file__).resolve().parent.parent


def version(value):
    value = value.removeprefix("v")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?", value):
        raise argparse.ArgumentTypeError("expected a version such as 0.1.4 or 0.1.4-rc.1")
    return value


def package(binary, target, release_version, output):
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"lagos-{release_version}-{target}.tar.gz"
    with archive.open("wb") as file:
        with gzip.GzipFile(filename="", mode="wb", fileobj=file, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as tar:
                for name, source in [("lagos", binary), ("LICENSE", ROOT / "LICENSE"), ("NOTICE", ROOT / "NOTICE")]:
                    info = tarfile.TarInfo(name)
                    info.size = source.stat().st_size
                    info.mode = 0o755 if name == "lagos" else 0o644
                    with source.open("rb") as content:
                        tar.addfile(info, content)
    return archive


def checksums(directory, release_version):
    names = {f"lagos-{release_version}-{target}.tar.gz" for target in TARGETS} | {"install.sh"}
    actual = {file.name for file in directory.iterdir()}
    if actual - {"SHA256SUMS"} != names:
        raise ValueError(f"release assets do not match required platforms: missing={sorted(names - actual)}, unexpected={sorted(actual - names - {'SHA256SUMS'})}")
    lines = []
    for name in sorted(names):
        file = directory / name
        if file.is_symlink() or not file.is_file() or file.stat().st_size == 0:
            raise ValueError(f"invalid release asset: {name}")
        lines.append(f"{hashlib.sha256(file.read_bytes()).hexdigest()}  {name}\n")
    (directory / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    pack = commands.add_parser("archive")
    pack.add_argument("--binary", type=pathlib.Path, required=True)
    pack.add_argument("--target", choices=TARGETS, required=True)
    pack.add_argument("--version", type=version, required=True)
    pack.add_argument("--output", type=pathlib.Path, required=True)
    sums = commands.add_parser("checksums")
    sums.add_argument("--directory", type=pathlib.Path, required=True)
    sums.add_argument("--version", type=version, required=True)
    args = parser.parse_args()
    if args.command == "archive":
        print(package(args.binary.resolve(strict=True), args.target, args.version, args.output))
    else:
        checksums(args.directory, args.version)


if __name__ == "__main__":
    main()
