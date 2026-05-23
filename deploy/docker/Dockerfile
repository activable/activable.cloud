# Multi-stage Dockerfile for activable GraphQL API server (pure Rust)

# Stage 1: Build Rust binary
FROM rust:1.95-bookworm AS builder

WORKDIR /workspace

# Copy workspace Cargo files first (cache deps layer)
COPY Cargo.toml Cargo.lock rust-toolchain.toml /workspace/

# Copy all crate sources
COPY crates /workspace/crates

# Build GraphQL server binary (release mode)
RUN cargo build --release -p activable-graphql

# Stage 2: Slim runtime — use same Debian version as builder to match glibc
FROM debian:bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy Rust binary from builder
COPY --from=builder /workspace/target/release/activable-graphql /app/activable-graphql

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/healthz || exit 1

EXPOSE 8080

CMD ["/app/activable-graphql"]
