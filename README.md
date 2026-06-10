# Activable

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![DCO](https://img.shields.io/badge/DCO-Signed-brightgreen.svg)](https://github.com/apps/dco)
[![Rust](https://img.shields.io/badge/Rust-1.95-orange.svg)](https://www.rust-lang.org)

**Cognitive knowledge graph for cloud infrastructure.** Activable ingests your cloud environment into a typed graph database and layers IAM security analysis, risk scoring, and attack path discovery on top — exposed via a single GraphQL API.

> *"Activable"* — Latin *activus* + *-abilis*: able to be activated. Your cloud infrastructure goes from inert API calls to a programmable reasoning substrate.

## Features

| | Feature | Detail |
|---|---------|--------|
| :globe_with_meridians: | **Cloud Ingestion** | YAML-driven AWS ingestion with native SDK enrichers (IAM, EC2, S3, Lambda). Extensible to any cloud provider. |
| :bar_chart: | **Knowledge Graph** | Postgres + [Apache AGE](https://age.apache.org/) graph database with canonical typed schema. Query with `findNode`, `walkEdges`, `pathFinder`, `blastRadius`, `subgraph`. |
| :shield: | **IAM Policy Evaluator** | Parliament-equivalent deep evaluation: Allow/Deny chains, permission boundary intersection, NotAction inversion, 10 condition operators, SCP support. |
| :warning: | **Dangerous Action Detection** | 20+ high-impact IAM actions cataloged across 3 severity tiers. Combo detection for multi-action escalation (e.g. PassRole + RunInstances). |
| :dart: | **Escalation Path Discovery** | [pathfinding.cloud](https://github.com/DataDog/managed-security-cloud-rules) YAML rule matching + `CanEscalateTo` graph edges for transitive privilege escalation chains. |
| :fire: | **Risk Scoring** | AML-inspired hybrid engine: 5 graph topology signals (blast radius, path-to-admin, dangerous actions, cross-account hops, permission surface) + rule boost. Per-principal composite score 0.0 -- 1.0 with severity bands. |
| :rocket: | **GraphQL API** | async-graphql + axum server. Queries: `riskScore`, `findings`, `blastRadius`, `walkEdges`, `pathFinder`. Mutations: `triggerIngest`, `refreshRiskScore`. |
| :whale: | **Kubernetes-native** | Helm chart for production deployment. Docker Compose for local development. |

## Architecture

```
  AWS / Cloud APIs
        │
        ▼
  ┌─────────────────┐     ┌──────────────────┐
  │  Ingestion       │     │  IAM Evaluator    │
  │  (activable-     │────▶│  (activable-      │
  │   ingest)        │     │   ingest-iam)     │
  └────────┬─────────┘     └────────┬──────────┘
           │                        │
           ▼                        ▼
  ┌──────────────────────────────────────────┐
  │          Knowledge Graph                  │
  │          (Postgres + Apache AGE)           │
  └────────────────────┬─────────────────────┘
                       │
                       ▼
  ┌──────────────────────────────────────────┐
  │          Risk Scoring Engine              │
  │          (activable-risk)                 │
  │  5 signals + pathfinding.cloud rules      │
  └────────────────────┬─────────────────────┘
                       │
                       ▼
  ┌──────────────────────────────────────────┐
  │          GraphQL API                      │
  │          (activable-graphql)              │
  └──────────────────────────────────────────┘
```

## Quick start

```bash
git clone https://github.com/activable-cloud/activable.cloud
cd activable.cloud

# Prerequisites: Rust 1.95, Docker
make setup          # install pre-commit hooks
make build          # build all crates

# Start the graph database
docker compose -f ops/compose/docker-compose.yml up -d db

# Run tests
make test           # 500+ tests
```

### Kubernetes deployment

```bash
kind create cluster --name activable
helm install activable ./ops/helm/activable
kubectl port-forward svc/activable-api 8080:8080
```

## Crates

| Crate | Description |
|-------|-------------|
| `activable-schema` | Node/edge type definitions, ARN canonicalizer, constraint validation |
| `activable-graph` | Postgres + Apache AGE driver, typed query API (BFS, Dijkstra, subgraph) |
| `activable-ingest` | YAML-driven AWS ingestion engine with native SDK enrichers |
| `activable-ingest-iam` | Parliament-equivalent IAM policy evaluator, escalation edge derivation |
| `activable-risk` | AML-inspired risk scoring: signal engine, rule engine, batch scorer |
| `activable-graphql` | GraphQL API server (async-graphql + axum) |

## Development

```bash
make lint           # cargo fmt --check + cargo clippy -D warnings
make test           # cargo test --workspace
make test-integration  # deploy Postgres+AGE, run integration suite
make verify         # CI-parity: lint + test + build
```

See [docs/code-standards.md](docs/code-standards.md) for conventions and [docs/onboarding.md](docs/onboarding.md) for a developer walkthrough.

## Contributing

1. Sign commits with DCO: `git commit -s`
2. Follow [code standards](docs/code-standards.md)
3. `make lint && make test` must pass
4. Open draft PR first; promote after CI green

## License

[Apache License 2.0](LICENSE)
