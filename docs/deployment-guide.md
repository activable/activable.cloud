# Deployment Guide

This document covers building, cross-compiling, and deploying Activable binaries.

## Binary Size Budget

**Target**: ≤ 50 MB stripped binary

Current baseline (initial build, with UniFFI + Cobra + OTel deps):
- **Linux/x86_64**: ~25 MB stripped
- **macOS/arm64**: ~22 MB stripped

Check size locally:
```bash
make size-check
# Output: Binary size: 25MB (limit: 50MB)
```

## Local Build

```bash
# Debug build (faster, larger)
cargo build --workspace
go build -o bin/activable ./go/cmd/activable

# Release build (slower, optimized)
cargo build --workspace --release
go build -ldflags "-s -w" -o bin/activable ./go/cmd/activable
```

## Cross-Compilation Matrix

Minimum supported targets:

| Target | Arch | Status |
|--------|------|--------|
| linux/amd64 | x86_64 | Primary (CI tested) |
| linux/arm64 | aarch64 | Supported |
| darwin/arm64 | Apple M1/M2 | Supported |

### Linux/x86_64

```bash
# On Linux machine
cargo build --release --target x86_64-unknown-linux-gnu
go build -o bin/activable-linux-amd64 ./go/cmd/activable

# From macOS (requires cross-compile setup)
rustup target add x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu
# Go cross-compile
GOOS=linux GOARCH=amd64 go build -o bin/activable-linux-amd64 ./go/cmd/activable
```

### Linux/arm64 (aarch64)

```bash
# On ARM Linux machine
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
GOOS=linux GOARCH=arm64 go build -o bin/activable-linux-arm64 ./go/cmd/activable

# From x86_64 macOS (requires cross)
brew install filosottile/cross/cross
cross build --release --target aarch64-unknown-linux-gnu
GOOS=linux GOARCH=arm64 go build -o bin/activable-linux-arm64 ./go/cmd/activable
```

### macOS/arm64 (Apple Silicon)

```bash
# On M1/M2 macOS
rustup target add aarch64-apple-darwin
cargo build --release --target aarch64-apple-darwin
GOOS=darwin GOARCH=arm64 go build -o bin/activable-darwin-arm64 ./go/cmd/activable

# Or native (automatic)
cargo build --release
go build -o bin/activable-darwin-arm64 ./go/cmd/activable
```

### macOS/x86_64 (Intel)

```bash
# On Intel macOS
rustup target add x86_64-apple-darwin
cargo build --release --target x86_64-apple-darwin
GOOS=darwin GOARCH=amd64 go build -o bin/activable-darwin-amd64 ./go/cmd/activable
```

## Docker Build

Multi-stage Dockerfile (recommended):

```dockerfile
# Build stage
FROM rust:latest as build-rust
WORKDIR /src
COPY crates crates/
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release

FROM golang:1.23 as build-go
WORKDIR /src
COPY go go/
COPY bindings bindings/
COPY go.mod go.sum ./
RUN CGO_ENABLED=0 go build -o bin/activable ./go/cmd/activable

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y postgresql-client
COPY --from=build-go /src/bin/activable /usr/local/bin/
ENTRYPOINT ["activable"]
```

Build:
```bash
docker build -t activable:latest .
docker run --rm activable verify
```

## Release Artifacts

When cutting a release:

```bash
# Tag the commit
git tag -s v0.1.0 -m "Release v0.1.0"

# GitHub Actions will auto-build and attach binaries
# Manual release (if CI not configured):
cargo build --release
go build -ldflags "-s -w" -o activable ./go/cmd/activable

# Create tarball
tar -czf activable-v0.1.0-linux-amd64.tar.gz \
    -C target/release libactivable_ffi.so activable

# Attach to GitHub Release
gh release create v0.1.0 activable-v0.1.0-linux-amd64.tar.gz
```

## Runtime Environment

### Postgres+AGE Connection

```bash
# Default (from docker-compose)
export ACTIVABLE_DB_HOST=localhost
export ACTIVABLE_DB_PORT=5433
export ACTIVABLE_DB_USER=activable
export ACTIVABLE_DB_PASSWORD=activable_dev
export ACTIVABLE_DB_NAME=activable

# Ingestor initialization reads these when implemented
```

### OpenTelemetry Endpoint

```bash
# Send traces to local OTEL collector
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317

# Or disable telemetry (no-op exporter)
export OTEL_EXPORTER_OTLP_ENDPOINT=""
```

## Performance Tuning

### Rust Release Profile

Already optimized in `Cargo.toml`:
```toml
[profile.release]
opt-level = 3          # Maximum optimization
lto = true             # Link-time optimization
codegen-units = 1      # Slower build, faster binary
strip = true           # Strip debug symbols
```

### Go Build Flags

```bash
# Minimal size
go build -ldflags "-s -w" ./go/cmd/activable

# With version info
VERSION=$(git describe --tags --always)
go build -ldflags "-s -w -X main.Version=$VERSION" ./go/cmd/activable
```

## Monitoring Build Size

Track binary size in CI:

```bash
# Store baseline
ls -lh bin/activable | awk '{print $5}' > size.baseline

# Compare in future builds
CURRENT=$(ls -lh bin/activable | awk '{print $5}')
echo "Baseline: $(cat size.baseline), Current: $CURRENT"
```

## Common Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| "binary too large (>50MB)" | Debug symbols not stripped | Use `go build -ldflags "-s -w"` |
| "undefined reference to libactivable_ffi" | Rust library not built | Run `cargo build --release` first |
| "GLIBC_2.34 not found" | glibc version mismatch | Build in matching glibc container or use musl target |
| Slow macOS build | ccache/incremental compile | Use `cargo build -j1` to debug, otherwise accept slower |

## Continuous Integration

GitHub Actions CI automatically builds and tests for:
- Linux (ubuntu-latest)
- macOS (macos-latest)

See `.github/workflows/ci.yml` for full matrix and build DAG.

---

**Next:** See [System Architecture](./system-architecture.md) for runtime topology and deployment architecture.
