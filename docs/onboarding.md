# Onboarding — Rust + Go + UniFFI Development Loop

Welcome to Activable! This guide covers the first 30 minutes of development setup for experienced polyglot engineers, or 4–6 hours for engineers new to Rust or Go.

## 5 Min: Verify Toolchains

```bash
# Rust (1.75+)
rustup update stable
rustup default stable
rustup show

# Go (1.23+)
go version

# Docker (for Postgres+AGE)
docker --version
docker compose version
```

## 10 Min: Clone and `make setup`

```bash
git clone https://github.com/activable-cloud/activable.cloud
cd activable.cloud

# Install dependencies
make setup

# This runs:
# - rustup show (verify Rust)
# - go version (verify Go)
# - pre-commit install --install-hooks (DCO + linting hooks)
```

## 15 Min: Build All

```bash
# Rust workspace
cargo build --workspace --release

# Go CLI (with CGO disabled for simplicity)
make build

# Generates UniFFI bindings
make bindgen
```

## 20 Min: Run Tests

```bash
# Rust tests
cargo test --workspace

# Go tests
go test -race ./go/...

# Linting (both)
make lint

# Smoke test
make smoke
```

## 25 Min: Start Postgres+AGE

```bash
# Docker Compose brings up the database
docker compose -f ops/compose/docker-compose.yml up -d db

# Wait for health check
docker compose -f ops/compose/docker-compose.yml logs db

# Verify connectivity
psql -h localhost -p 5433 -U activable -d activable -c "SELECT 1;"
```

You're ready to develop!

## Development Loop

### Making Changes

**Rust:**
```bash
# Edit crates/activable-schema/src/arn.rs (or any crate)
vim crates/activable-schema/src/arn.rs

# Format
cargo fmt --all

# Check
cargo clippy --all-targets -- -D warnings

# Test
cargo test --workspace
```

**Go:**
```bash
# Edit go/cmd/activable/main.go
vim go/cmd/activable/main.go

# Format
gofmt -w ./go

# Lint
golangci-lint run ./go/...

# Test
go test ./go/...
```

**Bindings (after FFI changes):**
```bash
# Modify crates/activable-ffi/src/activable.udl or crates/activable-ffi/src/lib.rs
# Regenerate:
make bindgen
```

### Committing

All commits require DCO sign-off:

```bash
git add -A
git commit -s -m "feat(schema): add ARN parser"
# Pre-commit hooks will check:
# - rustfmt (if Rust files)
# - clippy (if Rust files)
# - gofmt (if Go files)
# - golangci-lint (if Go files)
# - DCO Signed-off-by trailer
```

## Debugging Cross-FFI Issues

See [debugging.md](./debugging.md) for:
- GDB attach to Rust panics
- Reading panic backtraces across the FFI boundary
- Common bindgen failure modes
- Platform-specific `.so` / `.dylib` issues

## Common Gotchas

### Rust ↔ Go dylib path
The Makefile detects platform and sets:
- **Linux**: `target/release/libactivable_ffi.so`
- **macOS**: `target/release/libactivable_ffi.dylib`
- **Windows**: `target/release/activable_ffi.dll`

If Go build fails with "library not found", check the Makefile `RUST_DYLIB` variable:
```bash
make clean
make build
```

### Pre-commit hook mismatch
If pre-commit is missing dependencies:
```bash
# Reinstall
pre-commit install --install-hooks
pre-commit run --all-files

# Or skip for emergency (document in commit message):
git commit --no-verify
```

### Postgres+AGE not responding
```bash
# Check container
docker compose -f ops/compose/docker-compose.yml ps

# Restart
docker compose -f ops/compose/docker-compose.yml restart db

# Tail logs
docker compose -f ops/compose/docker-compose.yml logs -f db
```

## Next Steps

1. Pick a feature from `plans/ROADMAP.md` (local only)
2. Create a branch: `git checkout -b feat/your-feature`
3. Follow the development loop above
4. Open a draft PR: `gh pr create --draft`
5. Once CI passes, promote: `gh pr ready <PR_NUMBER>`

## Resources

- [Code Standards](./code-standards.md) — naming, formatting, conventions
- [Debugging Guide](./debugging.md) — cross-FFI debugging
- [Deployment Guide](./deployment-guide.md) — cross-compilation, binary size
- [System Architecture](./system-architecture.md) — graph schema, FFI boundary, runtime
- [Rust Book](https://doc.rust-lang.org/book/) — Rust fundamentals
- [Go Docs](https://go.dev/doc/) — Go fundamentals
- [UniFFI Guide](https://mozilla.github.io/uniffi-rs/) — FFI binding generation

---

Questions? Ask in Discussions or reach out to the maintainers.
