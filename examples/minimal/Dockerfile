ARG LAGOS_IMAGE=ghcr.io/lagos-sh/lagos:0.1.5
FROM ${LAGOS_IMAGE}
COPY gateway.yml /etc/lagos/gateway.yml
RUN ["lagos", "validate", "--allow-unset"]
