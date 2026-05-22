# Activable — Cloud Attack Graph Platform

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![DCO](https://img.shields.io/badge/DCO-Signed-brightgreen.svg)](https://github.com/apps/dco)

Activable is an open-source platform for discovering, modeling, and analyzing cloud attack paths. Built on **Apache AGE** (PostgreSQL graph extension) with a **Rust core** (schema, graph, IAM evaluator) and **Go CLI/ingestion** layer connected via **UniFFI**.

## Quick Start (60 seconds)

### Prerequisites

- **Rust 1.75+**: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Go 1.23+**: https://go.dev/dl
- **Docker** (for Postgres+AGE): https://www.docker.com

### Setup

```bash
# Clone and navigate
git clone https://github.com/activable-cloud/activable.cloud
cd activable.cloud

# Install dev tooling
make setup

# Build
make build

# Start Postgres+AGE
docker compose -f infra/compose/docker-compose.yml up -d db

# Smoke test
make verify
```

### Rust Development

```bash
# Check Rust setup
rustup show

# Build Rust crates
cargo build --workspace

# Run tests
cargo test --workspace

# Format and lint
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings

# Regenerate UniFFI bindings (after modifying crates/activable-ffi/src/activable.udl)
make bindgen
```

### Go Development

```bash
# Check Go setup
go version

# Build CLI
go build -o bin/activable ./go/cmd/activable

# Run tests
go test -race ./go/...

# Format and lint
gofmt -l ./go
golangci-lint run ./go/...
```

### Docker Compose

Start the local Postgres+AGE database:

```bash
docker compose -f infra/compose/docker-compose.yml up -d db
docker compose -f infra/compose/docker-compose.yml logs -f db
```

Stop:

```bash
docker compose -f infra/compose/docker-compose.yml down
```

## Make Targets

```bash
make setup              # Install dependencies and pre-commit hooks
make lint              # Check code formatting and linting
make test              # Run tests
make build             # Build all (Rust + Go)
make bindgen           # Regenerate UniFFI bindings
make verify            # Smoke test
make test-ffi-stability # Concurrent FFI stress test (MUST PASS on every PR)
make size-check        # Verify binary < 50MB
make clean             # Clean build artifacts
```

## Project Structure

```
activable.cloud/
├── crates/                    # Rust workspace
│   ├── activable-schema/      # Node/edge types, ARN canonicalizer
│   ├── activable-graph/       # PostgreSQL + Apache AGE driver
│   ├── activable-iam-eval/    # IAM evaluator (Parliament port — pending implementation)
│   └── activable-ffi/         # UniFFI boundary (Rust → Go)
├── go/                        # Go module
│   ├── cmd/activable/         # CLI entry point
│   ├── internal/ingest/       # Ingestion framework
│   ├── internal/telemetry/    # OpenTelemetry setup
│   └── internal/api/          # REST API
├── bindings/                  # UniFFI-generated Go bindings (committed)
├── infra/
│   ├── compose/               # Docker Compose (Postgres+AGE)
│   └── iam/                   # Least-privilege IAM policy
├── scripts/                   # CI/build helper scripts
├── docs/                      # Documentation
│   ├── code-standards.md
│   ├── deployment-guide.md
│   ├── debugging.md
│   ├── onboarding.md
│   └── system-architecture.md
└── .github/workflows/         # GitHub Actions CI
```

## Development Workflow

1. **Branch**: `git checkout -b feat/your-feature`
2. **Code**: Make changes following `docs/code-standards.md`
3. **Test**: `make lint && make test`
4. **Commit**: `git commit -s -m "feat(component): description"` (DCO sign-off required)
5. **Push & PR**: `git push -u origin feat/your-feature && gh pr create --draft`
6. **Review**: CI checks and local verification before promoting from draft

## Documentation

- **[Onboarding](docs/onboarding.md)** — 30-min walkthrough of Rust+Go+UniFFI dev loop
- **[Debugging](docs/debugging.md)** — Cross-FFI debugging: GDB, panic traces, bindgen failures
- **[Code Standards](docs/code-standards.md)** — Naming, style, formatting conventions
- **[Deployment Guide](docs/deployment-guide.md)** — Cross-compilation matrix, binary size budget, runtime topology
- **[System Architecture](docs/system-architecture.md)** — Schema, FFI boundary, runtime topology
- **[Roadmap](plans/ROADMAP.md)** — High-level milestones and feature planning *(local only — plans/ is gitignored)*

## License

Licensed under Apache License 2.0 — see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please:

1. Sign commits with DCO: `git commit -s`
2. Follow `docs/code-standards.md` conventions
3. Ensure `make lint && make test` passes
4. Open draft PR first; promote after CI green

## Roadmap

Activable is in active development. Current focus:

- Graph schema and AWS IAM ingestion with Postgres+AGE backend
- Parliament integration (IAM policy evaluator) — planned
- Attack-path queries and rule engine — planned
- Kubernetes ingestion and IRSA bridge — planned
- LLM/agent layer — planned
- REST API and web UI — planned

See `plans/ROADMAP.md` for details *(local only)*.

## Support

- **Issues**: GitHub Issues (public)
- **Discussions**: GitHub Discussions (community)
- **Security**: See SECURITY.md (if applicable)

---

Built with 🦀 Rust, 🐹 Go, and 📊 Apache AGE.
