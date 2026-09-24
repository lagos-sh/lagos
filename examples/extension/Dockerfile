ARG LAGOS_BUILDER=ghcr.io/lagos-sh/lagos-builder:0.1.5
ARG LAGOS_RUNTIME=ghcr.io/lagos-sh/lagos:0.1.5
FROM ${LAGOS_BUILDER} AS build
WORKDIR /work
COPY ext/ /work/ext/
RUN lagos-build /work/ext

FROM ${LAGOS_RUNTIME}
COPY --from=build /out/lagos /usr/local/bin/lagos
COPY gateway.yml /etc/lagos/gateway.yml
RUN ["lagos", "validate", "--allow-unset"]
