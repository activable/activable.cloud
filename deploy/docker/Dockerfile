# Stage 1: Build Rust FFI
FROM rust:1.95 AS rust-builder
WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ crates/
RUN cargo build --release -p activable-ffi
# Output: /app/target/release/libactivable_ffi.so

# Stage 2: Build Go server
FROM golang:1.23 AS go-builder
WORKDIR /app
COPY go/ go/
COPY bindings/ bindings/
COPY go.mod go.sum ./
# Copy Rust dylib from stage 1
COPY --from=rust-builder /app/target/release/libactivable_ffi.* /usr/local/lib/
ENV CGO_ENABLED=1
ENV CGO_LDFLAGS="-L/usr/local/lib"
ENV LD_LIBRARY_PATH="/usr/local/lib"
RUN cd go && go build -o /app/activable ./cmd/activable

# Stage 3: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=rust-builder /app/target/release/libactivable_ffi.* /usr/local/lib/
COPY --from=go-builder /app/activable /usr/local/bin/activable
ENV LD_LIBRARY_PATH="/usr/local/lib"
EXPOSE 8080
CMD ["activable", "serve"]
