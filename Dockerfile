# Build
FROM rust:1.85-slim-bookworm AS build
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
    && cargo build --release --bin lagos \
    && rm -rf crates/lagos-core/src crates/lagos/src

COPY crates crates
RUN touch crates/lagos-core/src/lib.rs crates/lagos/src/main.rs \
    && cargo build --release --bin lagos

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
