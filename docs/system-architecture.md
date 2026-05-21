# System Architecture

High-level design of Activable's polyglot architecture: Rust core, Go CLI/ingestion, Postgres+AGE backend, UniFFI boundary.

## Component Diagram

```
┌─────────────────────────────────────────────────────────────┐
│ Go Layer (CLI, Ingestion, API)                              │
├─────────────────────────────────────────────────────────────┤
│ cmd/activable        ← CLI entry point (Cobra)              │
│ internal/ingest/     ← AWS ingestion framework              │
│ internal/telemetry/  ← OpenTelemetry setup                  │
│ internal/api/        ← REST API (Slice F)                   │
└────────────────┬────────────────────────────────────────────┘
                 │ UniFFI bindings (type-safe, in-process)
                 ↓
┌─────────────────────────────────────────────────────────────┐
│ Rust Layer (Core, Schema, Graph, IAM Eval)                 │
├─────────────────────────────────────────────────────────────┤
│ activable-schema/   ← Nodes, edges, ARN canonicalizer      │
│ activable-graph/    ← Postgres + Apache AGE driver         │
│ activable-iam-eval/ ← Parliament port (Slice B stub)       │
│ activable-ffi/      ← UniFFI surface                        │
└────────────────┬────────────────────────────────────────────┘
                 │ SQL (Cypher via AGE)
                 ↓
┌─────────────────────────────────────────────────────────────┐
│ Postgres 16 + Apache AGE (Graph Database)                  │
├─────────────────────────────────────────────────────────────┤
│ - Named graph: "aws_graph"                                  │
│ - Nodes: Principal, Resource, Permission, etc. (12 types)  │
│ - Edges: CanAssume, CanAccess, Contains, etc. (17 types)   │
│ - Indexes on node IDs, edge types, timestamps              │
└─────────────────────────────────────────────────────────────┘
```

## Runtime Topology

### Single Machine (Development)

```
┌─────────────────┐
│  activable CLI  │  (compiled binary: Go + Rust via FFI)
└────────┬────────┘
         │
         ├─→ Call Rust version() via UniFFI
         ├─→ Initialize telemetry (OTel)
         └─→ Load ingestors (AWS, K8s, etc.)
                 │
                 ├─→ Fetch from AWS via SDK
                 └─→ Transform → Write to Postgres
                         │
                         ↓
                 ┌──────────────────┐
                 │ Postgres + AGE   │
                 │ (localhost:5433) │
                 └──────────────────┘
```

### Distributed (Future — Slice D+)

- **CLI runner**: One-shot ingestion, runs locally or in container
- **Postgres+AGE cluster**: Replicates across AZs (managed RDS or self-hosted)
- **API server**: Stateless; scales horizontally; queries graph
- **Telemetry**: Centralized OTel collector

## Graph Schema (Phase 3)

### Nodes (12 types)

| Type | Fields | Purpose |
|------|--------|---------|
| Principal | id (ARN), name, created_at | IAM user, role, service principal |
| Resource | id (ARN), type, name | S3 bucket, Lambda, EC2, etc. |
| Permission | sid, action, resource | Statement-level permission |
| ServicePrincipal | id, name, trust_policy | Cross-account trusted principal |
| FederatedProvider | id, name, saml_metadata | SAML/OIDC provider |
| AccessKey | id (public part), secret_hash, status | Long-term credentials |
| (7 more TBD Phase 3) | ... | ... |

### Edges (17 types)

| Type | From → To | Meaning |
|------|-----------|---------|
| CanAssume | Principal → Principal | AssumeRole permission |
| CanAccess | Principal → Resource | Action permitted on resource |
| Contains | Permission → Resource | Statement scopes resource |
| TrustedBy | Principal → ServicePrincipal | Cross-account trust relationship |
| SignedBy | AccessKey → Principal | Belongs to principal |
| (12 more TBD) | ... | ... |

See Phase 3 plan for full schema definition.

## FFI Boundary (UniFFI)

### Exported from Rust

Currently (Phase 1):
- `version() → String` — returns schema version

Will expand (Phases 2–6) to:
- Graph mutations: `create_node()`, `add_edge()`, `query_path()`
- IAM evaluation: `evaluate_policy()`, `check_permission()`
- Concurrency primitives: async Rust functions exposed safely to Go

### Type Mapping (Rust ↔ Go)

| Rust | Go |
|------|-----|
| `String` | `string` |
| `u64` | `uint64` |
| `Vec<T>` | `[]T` |
| `struct Arn` | Not exposed in Phase 1 (complex types deferred) |
| `async fn` | `func()` (blocking in Go, async in Rust) |

## Data Flow — Ingestion (Phase 5)

```
┌──────────────────┐
│ AWS Account      │
│ (IAM, STS, S3, │
│  EC2, Lambda)   │
└────────┬─────────┘
         │ aws-sdk-go-v2
         ↓
┌──────────────────────────────────┐
│ Go Ingestor                       │
│ - Fetch via AWS API              │
│ - Transform to node/edge structs │
│ - Deduplicate (idempotent)       │
└────────┬─────────────────────────┘
         │
         ├─→ Call Rust schema types via UniFFI
         ├─→ Validate ARN canonicalization
         └─→ Insert into Postgres
                 │
                 ↓
         ┌──────────────────┐
         │ PostgreSQL + AGE │
         │ aws_graph        │
         └──────────────────┘
```

## Concurrency Model

### Rust Side
- **Async runtime**: `tokio` (configured in workspace)
- **Thread safety**: All FFI-exported functions must be `Send + Sync`
- **Panic safety**: FFI boundary catches and propagates panics to Go

### Go Side
- **Goroutines**: 100+ concurrent ingestion workers (Phase 4)
- **Context timeout**: Cancellation propagated through FFI to Rust
- **Race detection**: CI runs `go test -race` on all Go tests

### FFI Stress Test
- Phase 1: `make test-ffi-stability` with 100+ concurrent goroutines
- Ensures safe concurrent calls across language boundary
- Catches segfaults, deadlocks, double-frees

## Telemetry (Phase 4)

OpenTelemetry instrumentation:

```
Go CLI/Ingestor
  ├─→ Trace: ingest_account (span)
  │    ├─→ Trace: fetch_iam_users (child span)
  │    ├─→ Trace: fetch_s3_buckets (child span)
  │    └─→ Call Rust FFI with trace context
  │         └─→ Rust records spans (Phase 6)
  │
  └─→ Metrics: ingestion_duration_ms, items_processed, errors
      └─→ Export to OTLP collector (gRPC)
```

## Deployment Targets

### Development
- Single `docker compose` stack: Postgres+AGE locally, CLI on host

### Testing (CloudGoat)
- Ephemeral AWS accounts created per test
- CLI ingests test account
- Graph validated against expected primitives

### Production (Slice F+)
- Managed Postgres (AWS RDS with read replicas)
- API server (Go stateless pods, HPA)
- Observability: datadog/honeycomb for traces + metrics

## Security Boundary

### Ingestion IAM Role (Phase 5)
```json
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetUser",
        "iam:ListUsers",
        "iam:ListAttachedUserPolicies",
        "s3:ListAllMyBuckets"
        // ... 20+ read-only IAM actions
      ],
      "Resource": "*"
    }
  ]
}
```

Least-privilege: read-only, no secrets, no console access.

### Graph Access Control (Slice F+)
- Multi-tenancy: separate graphs per customer (Postgres schemas or separate instances)
- RBAC on API: authenticated with JWT; scopes limit graph operations
- Audit logging: OTel traces with user identity

## Failure Modes & Recovery

| Failure | Detection | Recovery |
|---------|-----------|----------|
| Postgres down | Go ingestor fails; returns error | Retry with exponential backoff |
| Rust panic | FFI boundary catches; returns Go error | Log, alert; continue to next resource |
| AWS API timeout | Boto3/SDK timeout | Per-service retry budget (Phase 5) |
| Graph corruption | Checksum mismatch in Phase 6 test | Rollback and re-ingest from snapshot |

---

**Next:** See [Deployment Guide](./deployment-guide.md) for cross-compilation and runtime setup.
