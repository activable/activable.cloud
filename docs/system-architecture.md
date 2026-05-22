# System Architecture

Activable is a SaaS knowledge graph platform for cloud infrastructure. This document
describes the v1 substrate: Postgres + Apache AGE graph engine, Rust query primitives,
Go GraphQL API server, AWS ingestion, deployed on Kubernetes. See
[`docs/platform.md`](./platform.md) for the full platform thesis and enablement roadmap.

The v1 polyglot stack: Rust core (schema, graph driver, query primitives), Go (GraphQL
API server, ingestion), Postgres + Apache AGE storage, UniFFI boundary.

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

#### Carry-over for production loader (v1 status)

| # | Item | v1 Status |
|---|---|---|
| 1 | Wrap loading loop in explicit `BEGIN`/`COMMIT`. Define failure mode: atomic vs. resumable. | Resolved: Rust `activable-graph` loader uses transaction boundaries |
| 2 | Pre-flight validate edge endpoints; current INSERT silently inserts zero rows on missing endpoints. | Resolved: Transformer validates node IDs before edge creation |
| 3 | Make `BATCH_SIZE` (currently `500`) configurable via `--batch-size` CLI flag. | Resolved: `activable-graph` config accepts batch size parameter |
| 4 | Integrate `deadpool-postgres` connection pool for the loader. | Resolved: `activable-graph` uses `deadpool-postgres` for all DB access |
| 5 | Document `nextval()` sequence-ID gaps under concurrent load as expected behavior. | Resolved: Documented in this architecture file §Graph Schema |
| 6 | Add inline comment for `'"{}"'::agtype` literal syntax. | Resolved: Comments added in `query_builder.rs` escape functions |
| 7 | Parameterize Cypher UNWIND batches if statement-size becomes a hotspot. | Defer: Monitor in production; not a v1 blocker |
| 8 | Add checkpoint/resume logic for crash-resumability. | Defer: v1 uses atomic per-account ingestion; checkpoint logic is v2 |

### What this benchmark did NOT cover (revisit later)

- **Cold-cache latency.** All measurements are warm-cache.
- **Real AWS data shape.** Synthetic generator approximates fanout/cross-account distributions; real Organizations data may differ.
- **Storage growth.** Did not measure disk footprint at 1M+ edges; production schema work should profile.
- **Write throughput under sustained ingestion load.** The benchmark measured a one-shot bulk load, not steady-state writes.
- **Schema migrations on a live graph.** The benchmark used `drop_graph() + create_graph()`; production schema work needs online migration patterns.
- **Multi-tenancy isolation.** The benchmark used a single `cloud` named graph; multi-tenancy will need per-customer graphs or schemas.

## Graph Schema (v1 Production)

### Nodes (6 defined + 6 planned)

| Type | Fields | Purpose | v1 Status |
|------|--------|---------|-----------|
| Principal | id (ARN), name, created_at | IAM user, role, group | v1 ✓ |
| Resource | id (ARN), type, name | S3 bucket, Lambda, EC2, etc. | v1 ✓ |
| Permission | id (hash), policy_name, effect, actions | Statement-level permission | v1 ✓ |
| ServicePrincipal | id, name, trust_policy | Cross-account trusted principal | v1 ✓ |
| AccessKey | id (public part), status, created_at | Long-term credential | v1 ✓ |
| FederatedProvider | id, name, saml_metadata | SAML/OIDC provider | v1 ✓ |
| (Planned v2) | ... | ... | Policy, Group (as node), User Session, Bucket Policy, ... |

### Edges (5 defined + 12 planned)

| Type | From → To | Meaning | v1 Status |
|------|-----------|---------|-----------|
| CanAssume | Principal → Principal | AssumeRole permission | v1 ✓ |
| CanAccess | Principal → Resource | Action permitted on resource | v1 ✓ |
| Contains | Permission → Resource | Statement scopes resource | v1 ✓ |
| TrustedBy | Principal → ServicePrincipal | Cross-account trust relationship | v1 ✓ |
| SignedBy | AccessKey → Principal | Belongs to principal | v1 ✓ |
| (Planned v2) | ... | ... | IsAdmin, HasMFA, InGroup, Attached, IsPublic, ... |

**Schema design:** Node and edge types are locked for v1. All v1 ingesters (IAM, STS) emit only these 6 node types + 5 edge types. Future service ingesters (S3, KMS, Lambda) will remain on v1 types until v2 schema expansion.

## FFI Boundary (UniFFI)

### Exported from Rust (v1)

**Version & metadata:**
- `version() → String` — returns schema version (e.g., "v1.0.0")

**Graph queries (via `activable-graph` crate):**
- `find_by_id(label, id) → Option<NodeRef>` — lookup node by type + ID
- `walk_edges(start, edge_types, direction, depth_limit) → Vec<NodeRef>` — reachable nodes (streaming)
- `path_finder(start, end, edge_pattern, max_hops) → Vec<Path>` — shortest paths
- `shortest_path_length(start, end, max_hops) → Option<u32>` — path length only
- `blast_radius(node, edge_types, max_hops) → Vec<NodeRef>` — impact analysis

All exported functions are async-safe and thread-safe; Go calls them as blocking operations.

### Type Mapping (Rust ↔ Go)

| Rust | Go | Example |
|------|-----|---------|
| `String` | `string` | ARN: `"arn:aws:iam::123456789012:user/alice"` |
| `Option<T>` | `*T` (nil if none) | `find_by_id` returns `*NodeRef` |
| `Vec<T>` | `[]T` | paths as `[]Path` |
| `Result<T, E>` | `(T, error)` | Query error handling |
| `async fn` | `func()` (blocking) | All queries block in Go; executor runs on tokio runtime |

## Data Flow — Ingestion

```
┌─────────────────────────────────────┐
│ AWS Account                         │
│ (IAM, STS, S3, EC2, Lambda, etc.)  │
└────────┬────────────────────────────┘
         │
         ├─→ aws-sdk-go-v2 (API client)
         ↓
┌──────────────────────────────────────────────┐
│ Go Ingestion Framework                        │
│ go/internal/ingest/aws/<service>/             │
└────┬─────────────────┬──────────┬─────────────┘
     │                 │          │
     ↓                 ↓          ↓
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ <service>    │ │ <service>    │ │ <service>    │
│ _fetcher.go  │ │_transformer  │ │ _ingester.go │
│              │ │ .go          │ │              │
│ AWS API      │ │              │ │ Implement    │
│ calls        │ │ Transform    │ │ Ingester     │
│ Pagination   │ │ AWS types →  │ │ interface:   │
│              │ │ ResourceSpec │ │ - Service()  │
│              │ │ + EdgeSpec   │ │ - enumerate()│
│              │ │              │ │ - required   │
│              │ │              │ │   IAM actions│
└──────────────┘ └──────────────┘ └──────┬───────┘
                                          │
                                          ├─→ Rust schema validation
                                          │   (ARN canonicalization)
                                          └─→ Postgres insert
                                                   │
                                                   ↓
                                          ┌──────────────────┐
                                          │ PostgreSQL + AGE │
                                          │ aws_graph        │
                                          │ (Cypher UNWIND)  │
                                          └──────────────────┘
```

**Three-stage ingestion pattern (per service):**

1. **Fetcher** (`<service>_fetcher.go`): AWS API calls with pagination and semaphore-limited concurrency.
2. **Transformer** (`<service>_transformer.go`): Pure functions converting AWS types to `ResourceSpec` + `EdgeSpec`.
3. **Ingester** (`<service>_ingester.go`): Implements `Ingester` interface; streams results via channels to the graph database.

See [Developer Guide: Adding a Service](./developer-guide-add-service.md) for the pattern reference.

## Query API (v1 Primitives)

The `activable-graph` crate exposes five core query primitives via `GraphClient` (Rust) and UniFFI (Go):

| Primitive | Signature | Latency (p95, 100k-node graph) | Use Case |
|-----------|-----------|-----------|----------|
| `find_by_id` | `(label, id) → Option<NodeRef>` | ~1 ms | Node existence check, hydration |
| `walk_edges` | `(start, edge_types[], direction, depth) → Vec<NodeRef>` | ~1 ms | Neighborhood discovery, blast radius |
| `path_finder` | `(start, end, edge_pattern[], max_hops) → Vec<Path>` | ~20 ms (3-hop), ~1 ms (6-hop) | Attack surface analysis |
| `shortest_path_length` | `(start, end, max_hops) → Option<u32>` | ~1 ms | Isolation verification |
| `blast_radius` | `(node, edge_types[], max_hops) → Vec<NodeRef>` | ~5 ms | Impact scope (all reachable) |

**Design rule:** All queries return structural data (IDs, path lengths) not full property blobs. Property hydration is lazy (pull from source of truth on demand).

**Performance note:** 3-hop queries with full property materialization reach ~94 ms p95; v1 API design absorbs this via pagination (first-50-results pattern).

See [Developer Guide: Adding a Query](./developer-guide-add-query.md) for the pattern reference.

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
- Run: `make test-integration` to validate locally

### Testing (CloudGoat + CI)
- Ephemeral AWS accounts created per test run
- CLI ingests test account; verifies schema compliance
- Graph validated against expected primitives + cardinality checks
- Set `AGE_TEST_URL=postgres://...` to enable Rust integration tests
- CI runs: `cargo test --test '*'`, `go test -race ./...` with live AGE instance

### Production
- Managed Postgres (AWS RDS with read replicas)
- GraphQL API server (Go stateless pods, HPA)
- Ingestion job (Kubernetes cronjob or event-driven)
- Observability: OpenTelemetry traces (Datadog, Honeycomb, or self-hosted collector)

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
| AWS API timeout | SDK timeout (per-service budget) | Retry; skip on permanent error |
| Graph corruption | Checksum mismatch in integrity test | Rollback and re-ingest from snapshot |

## v1 Substrate Components

The v1 release includes:

1. **`activable-schema`** (Rust crate) — ARN types, node + edge definitions, schema versioning
2. **`activable-graph`** (Rust crate) — Postgres + Apache AGE driver, query builder, five query primitives
3. **`activable-ffi`** (Rust crate) — UniFFI surface for Go
4. **Go ingestion framework** (`go/internal/ingest/aws/`) — Pluggable service ingesters; IAM + STS included
5. **Go GraphQL API** (`go/internal/api/`) — Query endpoint, REST → FFI translation (future v1.1)
6. **Helm chart** (`deploy/helm/`) — Kubernetes deployment for API server + ingestion job

---

## Developer Guides

- [Adding a New AWS Service Ingester](./developer-guide-add-service.md) — Step-by-step guide for implementing a new service ingester following the fetch/transform/ingest pattern.
- [Adding a New Query Primitive](./developer-guide-add-query.md) — Step-by-step guide for adding a query to `CypherBuilder` + `GraphClient` with tests and FFI exposure.

**Next:** See [Deployment Guide](./deployment-guide.md) for cross-compilation and runtime setup.
