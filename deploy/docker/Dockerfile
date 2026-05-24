# syntax=docker/dockerfile:1.4
# Multi-stage Dockerfile for activable GraphQL API server (pure Rust)

# Stage 1: Build Rust binary with BuildKit cache mounts
FROM rust:1.95-bookworm AS builder

WORKDIR /workspace

# Copy workspace files (small layer, rarely changes)
COPY Cargo.toml Cargo.lock rust-toolchain.toml /workspace/

# Copy all crate sources
COPY crates /workspace/crates

# Build with cargo registry + target cache mounts (BuildKit) and release-fast profile
# (no LTO, parallel codegen — ~3x faster builds than release, ~10% slower runtime)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/workspace/target \
    cargo build --profile release-fast -p activable-graphql && \
    cp /workspace/target/release-fast/activable-graphql /tmp/activable-graphql

# Stage 2: Slim runtime
FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
    ca-certificates \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy Rust binary from builder
COPY --from=builder /tmp/activable-graphql /app/activable-graphql

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/healthz || exit 1

EXPOSE 8080

CMD ["/app/activable-graphql"]
