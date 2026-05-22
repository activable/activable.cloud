# Multi-stage Dockerfile for activable GraphQL API server

# Stage 1: Build Rust FFI library
FROM rust:1.75 as rust-builder

WORKDIR /workspace

# Copy Rust crate
COPY crates /workspace/crates
COPY Cargo.toml Cargo.lock /workspace/

# Build FFI library (release mode)
RUN cd /workspace && cargo build --release --lib -p activable-ffi

# Output: /workspace/target/release/libactivable_ffi.so

# Stage 2: Build Go binary
FROM golang:1.25 as go-builder

WORKDIR /workspace

# Copy Go module files
COPY go.mod go.sum /workspace/

# Copy Go source
COPY go /workspace/go
COPY bindings /workspace/bindings

# Copy Rust library from stage 1
COPY --from=rust-builder /workspace/target/release/libactivable_ffi.so /workspace/lib/

# Set environment for CGo
ENV CGO_ENABLED=1 \
    CGO_LDFLAGS="-L/workspace/lib" \
    LD_LIBRARY_PATH=/workspace/lib

# Build Go binary
RUN go build -o /workspace/activable-server ./go/cmd/activable

# Stage 3: Runtime image
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Go binary from stage 2
COPY --from=go-builder /workspace/activable-server /app/

# Copy Rust library from stage 1
COPY --from=rust-builder /workspace/target/release/libactivable_ffi.so /app/lib/

# Create lib directory for runtime
RUN mkdir -p /app/lib && chmod 755 /app/lib

# Set library path
ENV LD_LIBRARY_PATH=/app/lib

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/healthz || exit 1

# Expose GraphQL port
EXPOSE 8080

# Run the server
CMD ["/app/activable-server", "serve"]
