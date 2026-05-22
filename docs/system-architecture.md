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
│ internal/api/        ← REST API (API layer)                 │
└────────────────┬────────────────────────────────────────────┘
                 │ UniFFI bindings (type-safe, in-process)
                 ↓
┌─────────────────────────────────────────────────────────────┐
│ Rust Layer (Core, Schema, Graph, IAM Eval)                 │
├─────────────────────────────────────────────────────────────┤
│ activable-schema/   ← Nodes, edges, ARN canonicalizer      │
│ activable-graph/    ← Postgres + Apache AGE driver         │
│ activable-iam-eval/ ← Parliament port (IAM eval stub)      │
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

### Distributed (Future)

- **CLI runner**: One-shot ingestion, runs locally or in container
- **Postgres+AGE cluster**: Replicates across AZs (managed RDS or self-hosted)
- **API server**: Stateless; scales horizontally; queries graph
- **Telemetry**: Centralized OTel collector

## Graph Backend Decision: PG + Apache AGE (verdict 2026-05-21)

**Verdict: GO** — Postgres 16 + Apache AGE 1.6.0 passes all gate thresholds on a synthetic 100k-node AWS IAM graph with thousands-× margins. **No Vela-Kuzu fallback needed.**

| Gate | Threshold | Measured (100k, p95) | Margin |
|---|---|---|---|
| 6-hop variable-length traversal (single-thread) | < 2,000,000 µs | **442 µs** | 4,524× |
| 6-hop variable-length traversal (concurrent, 4×25) | < 2,500,000 µs | **697 µs** | 3,587× |
| Shortest-path (single-thread) | < 3,000,000 µs | **367 µs** | 8,174× |

Full methodology, query mix, hardware fingerprint, and reproduction commands: [`spike/graph-backend/results.md`](../spike/graph-backend/results.md).

### Why the margins are this large (and what they don't promise)

The whole reason this spike existed is the documented AGE perf cliff on variable-length paths ([apache/age#195](https://github.com/apache/age/issues/195)). Our synthetic graph didn't trigger it. Reasons:

1. **AWS IAM topology is DAG-like with shallow fanout.** Principal→Role→Policy→Resource chains have bounded depth and concentrate fanout at top-level roles. The VLE cliff manifests on graphs with dense cross-connects forcing exponential path enumeration; we don't have that shape.
2. **`LIMIT 50` terminates traversal early.** Our query mix returns the first 50 matching paths, which short-circuits depth-first enumeration on the IAM-shaped graph.
3. **Warm-cache measurement.** We measure after 10 warmup runs per query. Cold-cache p95 will be higher; production cache hit rates depend on workload.

**Future action:** Revalidate on real AWS Organizations data once `activable-ingest` produces a non-synthetic graph. Treat the 3,500–8,000× margin as "comfortable pass on this synthetic workload," not as production headroom.

### Surprising observation — short queries are slower than long traversals

| Query (100k graph, single-thread p95) | Latency |
|---|---|
| 1-hop with `RETURN t LIMIT 100` (full property blobs) | **532 ms** |
| 3-hop with property materialization | **94 ms** |
| 6-hop var-len returning `length(path)` | **0.4 ms** |
| Shortest-path returning `length(path)` | **0.4 ms** |

Cause: `LOAD 'age'; SET search_path` runs per pool checkout (~120 ms amortized) + agtype property blob deserialization dominates when queries return full nodes. Traversal queries returning structural results (path lengths, node refs) avoid the materialization cost.

**Production rules (carry into the API layer):**

- Reuse pool connections without `DISCARD ALL` so AGE session setup amortizes.
- Avoid full-property-blob returns on hot paths — return IDs or structural data and hydrate lazily.
- 3-hop queries are the worst case in our mix at 94 ms p95; design API pagination to absorb this.

### Bulk-load pattern (locked for production schema)

The Cypher `UNWIND $batch AS row MATCH ... CREATE` approach is **unusable at 100k+ scale** — AGE's Cypher planner does not use Postgres expression indexes for MATCH lookups, making each batch O(n_vertices). The benchmark switched to:

- SQL-level INSERT into AGE's underlying edge tables (`cloud."HasPermission"`, `cloud."CanAssume"`) via `ag_catalog._graphid(<label_oid>, <id_sequence>)`.
- Expression indexes on `agtype_access_operator(properties, '"id"'::agtype)` for vertex-ID lookup by JOIN.
- Vertex inserts still use Cypher `UNWIND` (acceptable because each row is independent; no MATCH lookup needed).

Implementation: [`spike/graph-backend/src/load_pg_age.rs`](../spike/graph-backend/src/load_pg_age.rs). Code review of the SQL fast-path loader: APPROVED_WITH_CAVEATS — 0 priority-0 (security/correctness), 8 priority-1 (production-readiness) items recorded below. (Full report in `plans/reports/` — local artifact, not in repository.)

#### Carry-over for production loader

| # | Item | Owner |
|---|---|---|
| 1 | Wrap loading loop in explicit `BEGIN`/`COMMIT`. Define failure mode: atomic vs. resumable. | production loader impl |
| 2 | Pre-flight validate edge endpoints; current INSERT silently inserts zero rows on missing endpoints. | production loader impl |
| 3 | Make `BATCH_SIZE` (currently `500`) configurable via `--batch-size` CLI flag. | production loader impl |
| 4 | Integrate `deadpool-postgres` connection pool for the loader (currently single `tokio_postgres::Client`). | production loader impl |
| 5 | Document `nextval()` sequence-ID gaps under concurrent load as expected behavior. | Docs |
| 6 | Add inline comment for `'"{}"'::agtype` literal syntax at `load_pg_age.rs:393`. | production loader impl |
| 7 | Parameterize Cypher UNWIND batches (~50 KB per 500-row batch) if statement-size becomes a hotspot. | Defer until benchmarked at production scale |
| 8 | Add checkpoint/resume logic OR `ON CONFLICT` / pre-flight dedup if crash-resumability is required (application-level checkpointing tracks last committed batch; SQL-level idempotency uses `ON CONFLICT`). | production loader impl |

### What this benchmark did NOT cover (revisit later)

- **Cold-cache latency.** All measurements are warm-cache.
- **Real AWS data shape.** Synthetic generator approximates fanout/cross-account distributions; real Organizations data may differ.
- **Storage growth.** Did not measure disk footprint at 1M+ edges; production schema work should profile.
- **Write throughput under sustained ingestion load.** The benchmark measured a one-shot bulk load, not steady-state writes.
- **Schema migrations on a live graph.** The benchmark used `drop_graph() + create_graph()`; production schema work needs online migration patterns.
- **Multi-tenancy isolation.** The benchmark used a single `cloud` named graph; multi-tenancy will need per-customer graphs or schemas.

## Graph Schema (Production)

### Nodes (12 types)

| Type | Fields | Purpose |
|------|--------|---------|
| Principal | id (ARN), name, created_at | IAM user, role, service principal |
| Resource | id (ARN), type, name | S3 bucket, Lambda, EC2, etc. |
| Permission | sid, action, resource | Statement-level permission |
| ServicePrincipal | id, name, trust_policy | Cross-account trusted principal |
| FederatedProvider | id, name, saml_metadata | SAML/OIDC provider |
| AccessKey | id (public part), secret_hash, status | Long-term credentials |
| (7 more TBD) | ... | ... |

### Edges (17 types)

| Type | From → To | Meaning |
|------|-----------|---------|
| CanAssume | Principal → Principal | AssumeRole permission |
| CanAccess | Principal → Resource | Action permitted on resource |
| Contains | Permission → Resource | Statement scopes resource |
| TrustedBy | Principal → ServicePrincipal | Cross-account trust relationship |
| SignedBy | AccessKey → Principal | Belongs to principal |
| (12 more TBD) | ... | ... |

See production schema plan for full schema definition.

## FFI Boundary (UniFFI)

### Exported from Rust

Currently exported:
- `version() → String` — returns schema version

Will expand to:
- Graph mutations: `create_node()`, `add_edge()`, `query_path()`
- IAM evaluation: `evaluate_policy()`, `check_permission()`
- Concurrency primitives: async Rust functions exposed safely to Go

### Type Mapping (Rust ↔ Go)

| Rust | Go |
|------|-----|
| `String` | `string` |
| `u64` | `uint64` |
| `Vec<T>` | `[]T` |
| `struct Arn` | Not yet exposed (complex types deferred) |
| `async fn` | `func()` (blocking in Go, async in Rust) |

## Data Flow — Ingestion

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
- **Goroutines**: 100+ concurrent ingestion workers
- **Context timeout**: Cancellation propagated through FFI to Rust
- **Race detection**: CI runs `go test -race` on all Go tests

### FFI Stress Test
- `make test-ffi-stability` with 100+ concurrent goroutines
- Ensures safe concurrent calls across language boundary
- Catches segfaults, deadlocks, double-frees

## Telemetry

OpenTelemetry instrumentation:

```
Go CLI/Ingestor
  ├─→ Trace: ingest_account (span)
  │    ├─→ Trace: fetch_iam_users (child span)
  │    ├─→ Trace: fetch_s3_buckets (child span)
  │    └─→ Call Rust FFI with trace context
  │         └─→ Rust records spans (future)
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

### Production
- Managed Postgres (AWS RDS with read replicas)
- API server (Go stateless pods, HPA)
- Observability: datadog/honeycomb for traces + metrics

## Security Boundary

### Ingestion IAM Role
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

### Graph Access Control
- Multi-tenancy: separate graphs per customer (Postgres schemas or separate instances)
- RBAC on API: authenticated with JWT; scopes limit graph operations
- Audit logging: OTel traces with user identity

## Failure Modes & Recovery

| Failure | Detection | Recovery |
|---------|-----------|----------|
| Postgres down | Go ingestor fails; returns error | Retry with exponential backoff |
| Rust panic | FFI boundary catches; returns Go error | Log, alert; continue to next resource |
| AWS API timeout | Boto3/SDK timeout | Per-service retry budget |
| Graph corruption | Checksum mismatch in integrity test | Rollback and re-ingest from snapshot |

---

**Next:** See [Deployment Guide](./deployment-guide.md) for cross-compilation and runtime setup.
