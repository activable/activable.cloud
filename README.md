# Activable — Cognitive Knowledge Graph for Cloud Infrastructure

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![DCO](https://img.shields.io/badge/DCO-Signed-brightgreen.svg)](https://github.com/apps/dco)

Cloud APIs are inert — they answer one question at a time, leaving relationships,
trust chains, and cross-service dependencies invisible to any single caller. Activable
ingests a cloud environment's full state into a canonical knowledge graph and exposes
it as a reasoning substrate, so security analyzers, drift detectors, cost optimizers,
and AI agents can all act on it without duplicating ingestion. The cloud becomes
*activable*: queryable, programmable, agent-controllable.

## How it works

```
  Cloud APIs (AWS, K8s, ...)
         │
         │  ingestion workers (Go — provider SDKs)
         ▼
  ┌──────────────────────────┐
  │  Graph Ingestion Layer   │  ← fetch, transform, validate, insert
  │  (Go — aws-sdk-go-v2)   │
  └────────────┬─────────────┘
               │
               ▼
  ┌──────────────────────────┐
  │  Canonical Knowledge     │  ← typed nodes + edges (12 / 17 types)
  │  Graph (Postgres + AGE)  │    Principal, Resource, Permission, ...
  └────────────┬─────────────┘    CanAssume, CanAccess, Contains, ...
               │
               ▼
  ┌──────────────────────────┐
  │  GraphQL API (Go server) │  ← pathFinder, walkEdges, blastRadius,
  │  Kubernetes-deployed     │    subgraph, triggerIngest, ingestStatus
  └───────┬──────┬──────┬────┘
          │      │      │
  ┌───────┘      │      └───────────────┐
  ▼              ▼                      ▼
Attack-graph  Drift+IaC            FinOps / IAM
(v2 — #1)    (v2+)                right-sizing (v2+)
```

Each column on the bottom row is a separate enablement consumer. None calls cloud
APIs directly — they query the graph via the GraphQL API. See
[`docs/platform.md`](docs/platform.md) for the full platform thesis and enablement
model.

## Current state (v1)

v1 ships the substrate alone — deployed on Kubernetes:

- **Knowledge graph** — Postgres 16 + Apache AGE; canonical schema for cloud entities
  and relationships (12 node types, 17 edge types).
- **Rust query primitives** — typed crate with `findNode`, `walkEdges`, `pathFinder`,
  `blastRadius`, `subgraph` operations used by the API layer.
- **GraphQL API server** — Go server (Kubernetes-deployed) exposing query and mutation
  operations: `pathFinder`, `walkEdges`, `blastRadius`, `subgraph`, `triggerIngest`,
  `ingestStatus`.
- **AWS ingestion** — canonical first ingester (IAM, S3, Lambda, EC2, and more);
  triggered via `triggerIngest` mutation or on a scheduled cadence.

v1 is the foundation. Use-case consumers (attack-graph, drift detection, cost reasoning,
etc.) ship as v2+ enablements that consume the graph via the GraphQL API. See
[`docs/platform.md`](docs/platform.md) for the full description of what v1 includes and
what it intentionally defers.

## On the roadmap

Seven enablement consumers are designed to consume the v1 substrate. All are design
targets, not yet implemented. See [`plans/ROADMAP.md`](plans/ROADMAP.md) *(local-only —
plans/ is gitignored)* for per-enablement detail.

1. **Cloud attack-graph** — Parliament IAM eval + cross-domain path discovery + agentic
   purple-team loop. *v2 enablement #1. Design target, not yet implemented.*
2. **Drift detection + cloud-as-code reverse engineering** — walk IaC and live graph;
   surface diffs; synthesize Terraform/Pulumi from graph state.
   *Design target, not yet implemented.*
3. **Cost / FinOps reasoning** — annotate graph nodes with cost data; surface idle
   resources and expensive paths. *Design target, not yet implemented.*
4. **IAM right-sizing / least-privilege synthesis** — compare declared permissions
   against observed accesses; output policy diffs. *Design target, not yet implemented.*
5. **Agentic action layer** — typed tool surface (MCP-style) for LLM agents to query
   and propose cloud changes through gated pipelines.
   *Design target, not yet implemented.*
6. **Security-rule synthesis** — generate Sigma/Splunk detection rules from validated
   paths. *Design target, not yet implemented.*
7. **Multi-cloud (Azure + GCP)** — extend ingestion behind the same canonical schema.
   *Design target, not yet implemented.*

## About the name

"Activable" — Latin *activus* + *-abilis*: "able to be activated." Parallel to
*actionable* (able to be acted upon), but stronger: *activable* implies dormancy →
activation. Cloud infrastructure today is inert — APIs that answer one question at a
time, configurations scattered across consoles, knowledge locked in tribal memory and
runbooks. Activable inverts that. By projecting the cloud's full state into a canonical
knowledge graph, every resource, identity, dependency, and configuration becomes
addressable by reasoning systems. The cloud goes from "a stack of APIs you query
manually" to "a substrate that other tools — security analyzers, cost optimizers, drift
detectors, agents — can program against."

The first capability the platform enables is the **cloud attack graph**: cross-domain
attack-path discovery + agentic purple-teaming. More enablements are designed to share
the same graph (see [roadmap](./plans/ROADMAP.md)).

## Developer setup

### Prerequisites

- **Rust 1.95** (via `rustup`; matches `rust-toolchain.toml`): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Go 1.23+**: https://go.dev/dl
- **Docker** (for Postgres+AGE): https://www.docker.com
- **pre-commit**: `brew install pre-commit` (macOS) or `pipx install pre-commit`

### First-time setup

```bash
git clone https://github.com/activable-cloud/activable.cloud
cd activable.cloud

# Install pre-commit hooks (one-time per clone)
pre-commit install --install-hooks

# Build
make build

# Start Postgres+AGE
docker compose -f infra/compose/docker-compose.yml up -d db

# Smoke test
make smoke
```

### Local Kubernetes cluster

The full stack (graph database + GraphQL API server + ingestion workers) runs on
Kubernetes. For local development, use [Kind](https://kind.sigs.k8s.io/) or
[k3d](https://k3d.io/):

```bash
# Kind
kind create cluster --name activable

# k3d (alternative)
k3d cluster create activable

# Deploy via Helm chart (from repo root)
helm install activable ./infra/helm/activable \
  --set database.host=postgres-service \
  --set api.image.tag=local

# Port-forward the GraphQL API for local queries
kubectl port-forward svc/activable-api 8080:8080
```

Docker Compose (`infra/compose/docker-compose.yml`) is retained as a fallback for
starting Postgres + AGE in isolation when you need the database only:

```bash
docker compose -f infra/compose/docker-compose.yml up -d db
```

### Pre-commit hooks

The repo enforces basic quality locally via [pre-commit](https://pre-commit.com):

| Stage | Hooks |
|---|---|
| `pre-commit` | trailing whitespace, EOF newline, YAML/JSON parse, large-file guard, `cargo fmt --check`, `golangci-lint`, plan-taxonomy guard, shellcheck |
| `pre-push` | `cargo clippy -D warnings` (slower; gated to push) |
| `commit-msg` | `gitlint` |

To run all hooks manually against the whole tree:

```bash
pre-commit run --all-files
```

To bypass in an emergency (rare): `git commit --no-verify` / `git push --no-verify`. Never bypass on `main`.

### CI mirrors the local checks

The CI pipeline (`.github/workflows/ci.yml`) runs the same lints and tests, so contributors who skip `pre-commit install` still get caught at PR time. Locally is faster than waiting on CI.

## Language-specific development

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
make verify            # CI-parity check (lint + test + build)
make verify-rust       # Verify Rust only (fmt + clippy + test + build)
make verify-go         # Verify Go only (lint + test)
make smoke             # Smoke test (CLI version check)
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
│   ├── activable-ingest-iam/  # IAM ingestion (risk-scoring preparation)
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

- **[Platform Overview](docs/platform.md)** — Platform thesis, enablement model, v1 scope, and v2+ design targets
- **[System Architecture](docs/system-architecture.md)** — Schema, FFI boundary, runtime topology, graph backend decision
- **[Onboarding](docs/onboarding.md)** — 30-min walkthrough of Rust+Go+UniFFI dev loop
- **[Debugging](docs/debugging.md)** — Cross-FFI debugging: GDB, panic traces, bindgen failures
- **[Code Standards](docs/code-standards.md)** — Naming, style, formatting conventions
- **[Deployment Guide](docs/deployment-guide.md)** — Cross-compilation matrix, binary size budget, runtime topology
- **[Roadmap](plans/ROADMAP.md)** — High-level milestones and feature planning *(local only — plans/ is gitignored)*

## License

Licensed under Apache License 2.0 — see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please:

1. Sign commits with DCO: `git commit -s`
2. Follow `docs/code-standards.md` conventions
3. Ensure `make lint && make test` passes
4. Open draft PR first; promote after CI green

## Support

- **Issues**: GitHub Issues (public)
- **Discussions**: GitHub Discussions (community)
- **Security**: See SECURITY.md (if applicable)

---

Built with 🦀 Rust, 🐹 Go, and 📊 Apache AGE.
