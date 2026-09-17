# Build on a native Linux runner of each architecture, using musl for a static
# executable that does not depend on the user's glibc or Rust installation.
FROM rust:1.98-alpine AS build
RUN apk add --no-cache build-base cmake clang llvm-dev linux-headers perl pkgconf binutils
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/lagos-core/Cargo.toml crates/lagos-core/
COPY crates/lagos/Cargo.toml crates/lagos/
RUN mkdir -p crates/lagos-core/src crates/lagos/src \
    && echo '' > crates/lagos-core/src/lib.rs \
    && echo 'fn main(){}' > crates/lagos/src/main.rs \
    && cargo build --release --locked --bin lagos \
    && rm -rf crates/lagos-core/src crates/lagos/src
ARG LAGOS_SCHEMA_RELEASE=
ENV LAGOS_SCHEMA_RELEASE=${LAGOS_SCHEMA_RELEASE}
COPY crates crates
RUN find crates -name '*.rs' -exec touch {} + \
    && cargo build --release --locked --bin lagos \
    && readelf --program-headers target/release/lagos > /tmp/lagos-headers \
    && if grep -q INTERP /tmp/lagos-headers; then echo 'lagos must be statically linked' >&2; exit 1; fi

FROM scratch AS binary
COPY --from=build /src/target/release/lagos /lagos
