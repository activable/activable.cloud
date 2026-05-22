# Multi-stage Dockerfile for activable GraphQL API server

# Stage 1: Build Rust FFI library
FROM rust:1.95 AS rust-builder

WORKDIR /workspace

# Copy workspace Cargo files first (cache deps layer)
COPY Cargo.toml Cargo.lock rust-toolchain.toml /workspace/

# Copy all crate sources
COPY crates /workspace/crates

# Build FFI library (release mode — produces libactivable_ffi.so on Linux)
RUN cargo build --release --lib -p activable-ffi

# Stage 2: Build Go binary
FROM golang:1.25 AS go-builder

WORKDIR /workspace

# Copy Go module files first (cache deps layer)
COPY go.mod go.sum /workspace/
RUN go mod download

# Copy Go source + FFI bindings
COPY go /workspace/go
COPY bindings /workspace/bindings

# Copy Rust dylib from stage 1
COPY --from=rust-builder /workspace/target/release/libactivable_ffi.so /usr/local/lib/

# Build Go binary with CGo linking to Rust dylib
ENV CGO_ENABLED=1 \
    CGO_LDFLAGS="-L/usr/local/lib" \
    LD_LIBRARY_PATH=/usr/local/lib
RUN go build -o /workspace/activable-server ./go/cmd/activable

# Stage 3: Slim runtime
FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Go binary + Rust dylib
COPY --from=go-builder /workspace/activable-server /app/activable-server
COPY --from=rust-builder /workspace/target/release/libactivable_ffi.so /usr/local/lib/

# Ensure dynamic linker finds the dylib
RUN ldconfig

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/healthz || exit 1

EXPOSE 8080

CMD ["/app/activable-server", "serve"]
