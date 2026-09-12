# Build
# Must track rust-toolchain.toml. When it does not, the pinned channel is
# still honoured -- rustup just downloads it on every build, so the mismatch
# costs a toolchain download per layer miss and shows up as nothing but slow.
FROM rust:1.98-slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      pkg-config cmake perl make g++ clang libclang-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src

# Manifests first, so a source-only change does not refetch the dependency tree.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/lagos-core/Cargo.toml crates/lagos-core/
COPY crates/lagos/Cargo.toml      crates/lagos/
RUN mkdir -p crates/lagos-core/src crates/lagos/src \
    && echo ''            > crates/lagos-core/src/lib.rs \
    && echo 'fn main(){}' > crates/lagos/src/main.rs \
    && cargo build --release --locked --bin lagos \
    && rm -rf crates/lagos-core/src crates/lagos/src

COPY crates crates
# Every source file, not just the two crate roots: COPY preserves mtimes, so
# a module older than the stub build's artifacts is one Cargo will consider
# fresh and skip -- shipping a binary built from the empty stubs.
RUN find crates -name '*.rs' -exec touch {} + \
    && cargo build --release --locked --bin lagos

# Run
FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app
COPY --from=build /src/target/release/lagos /usr/local/bin/lagos
USER nonroot
EXPOSE 8080
# Mount a config and the defaults find it:
#   docker run -p 8080:8080 -v ./gateway.yml:/app/gateway.yml lagos
ENTRYPOINT ["/usr/local/bin/lagos"]
CMD ["run"]
