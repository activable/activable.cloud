# syntax=docker/dockerfile:1.4
# Slim runtime image for activable GraphQL API server.
# Binary is cross-compiled on the host (Mac arm64 -> linux/arm64) via
# `cargo zigbuild --target aarch64-unknown-linux-gnu --profile release-fast`
# and COPIED in directly — no in-container cargo build.

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    ca-certificates \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Pre-built binary (produced on host before `docker build`).
COPY target/aarch64-unknown-linux-gnu/release-fast/activable-graphql /app/activable-graphql

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/healthz || exit 1

EXPOSE 8080

CMD ["/app/activable-graphql"]
