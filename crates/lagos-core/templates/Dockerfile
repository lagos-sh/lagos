ARG LAGOS_IMAGE=ghcr.io/lagos-sh/lagos:{{LAGOS_VERSION}}
FROM ${LAGOS_IMAGE}
COPY gateway.yml /etc/lagos/gateway.yml
RUN ["lagos", "validate", "--allow-unset"]
