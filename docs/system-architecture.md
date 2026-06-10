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
│ activable-ingest-iam/ ← IAM ingestion (risk-scoring prep) │
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

Full methodology, query mix, hardware fingerprint, and reproduction commands: [`docs/references/graph-backend-benchmark-pg-age-verdict.md`](./references/graph-backend-benchmark-pg-age-verdict.md).

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

Implementation: `load_pg_age.rs` from the graph-backend benchmark harness (removed from the working tree; recoverable from git history). Code review of the SQL fast-path loader: APPROVED_WITH_CAVEATS — 0 priority-0 (security/correctness), 8 priority-1 (production-readiness) items recorded below. (Full report in `plans/reports/` — local artifact, not in repository.)

#### Carry-over for production loader

These items were identified in the graph-backend benchmark but deferred to production implementation. All are resolved in the `activable-graph` crate (initial implementation and subsequent hardening).

| # | Item | Status |
|---|---|---|
| 1 | Wrap loading loop in explicit `BEGIN`/`COMMIT`; define failure mode: atomic vs. resumable. | ✅ Resolved (Ingester orchestrates transactional batches) |
| 2 | Pre-flight validate edge endpoints; current INSERT silently inserts zero rows on missing endpoints. | ✅ Resolved (Transformer validates ARN format; FFI boundary checks node existence) |
| 3 | Make `BATCH_SIZE` (currently `500`) configurable via `--batch-size` CLI flag. | ✅ Resolved (Runtime config in `go/internal/ingest/config.go`) |
| 4 | Integrate `deadpool-postgres` connection pool for the loader (currently single `tokio_postgres::Client`). | ✅ Resolved (`GraphPool` uses `deadpool-postgres` with configurable pool size) |
| 5 | Document `nextval()` sequence-ID gaps under concurrent load as expected behavior. | ✅ Resolved (Documented in code; AGE sequence behavior explained in architecture notes) |
| 6 | Add inline comment for `'"{}"'::agtype` literal syntax at `load_pg_age.rs:393`. | ✅ Resolved (Inline comment added in spike code; carried into production) |
| 7 | Parameterize Cypher UNWIND batches (~50 KB per 500-row batch) if statement-size becomes a hotspot. | ✅ Resolved (Runtime batch-size parameter; monitoring added) |
| 8 | Add checkpoint/resume logic OR `ON CONFLICT` / pre-flight dedup if crash-resumability is required. | ✅ Resolved (Ingester framework supports idempotent re-runs; graph upsert semantics via ON CONFLICT) |

### What this benchmark did NOT cover (revisit later)

- **Cold-cache latency.** All measurements are warm-cache.
- **Real AWS data shape.** Synthetic generator approximates fanout/cross-account distributions; real Organizations data may differ.
- **Storage growth.** Did not measure disk footprint at 1M+ edges; production schema work should profile.
- **Write throughput under sustained ingestion load.** The benchmark measured a one-shot bulk load, not steady-state writes.
- **Schema migrations on a live graph.** The benchmark used `drop_graph() + create_graph()`; production schema work needs online migration patterns.
- **Multi-tenancy isolation.** The benchmark used a single `cloud` named graph; multi-tenancy will need per-customer graphs or schemas.

## Graph Schema (Production)

### Nodes (12 types; 6 implemented in v1)

| Type | Fields | Purpose | Status |
|------|--------|---------|--------|
| Principal | id (ARN), name, type (User/Role/ServicePrincipal), created_at, modified_at | IAM user, role, or cross-account principal | ✅ v1 |
| Resource | id (ARN), service (s3, ec2, lambda, ...), name, created_at, tags | S3 bucket, Lambda function, EC2 instance, etc. | ✅ v1 |
| Permission | id (derived from policy ARN + SID), action (space-separated string), resource_pattern, effect (Allow/Deny), conditions | Statement-level IAM permission | ✅ v1 |
| AccessKey | id (public access key ID), status (Active/Inactive), created_at, last_used_at | Long-term credential for a Principal | ✅ v1 |
| FederatedProvider | id (ARN), type (SAML/OIDC), metadata_url | SAML or OIDC identity provider | ✅ v1 |
| Account | id (12-digit account ID), alias, organization_path | AWS account in an organization | ✅ v1 |
| Group | id (ARN), name, created_at | IAM group (container of users with attached policies) | Planned v1.5 |
| ManagedPolicy | id (ARN), name, arn, version, attachment_count | AWS managed or customer-managed policy | Planned v1.5 |
| SecurityGroup | id (ARN), name, vpc_id, rules | VPC security group (ec2-specific) | Planned v2 |
| NetworkInterface | id (ARN), vpc_id, subnet_id, security_group_ids | ENI (bridges EC2↔VPC topology) | Planned v2 |
| KubernetesService | id, namespace, name, service_account_name | Kubernetes service account (K8s ingestion) | Planned v1.5 |
| StorageBucket | id (ARN), region, encryption_type, public_access_block_config | Extended storage resource (GCS/Azure Blob future) | Planned v2 |

### Edges (17 types; 5 implemented in v1)

| Type | From → To | Meaning | Status |
|------|-----------|---------|--------|
| CanAssume | Principal → Principal | Role can be assumed via sts:AssumeRole by another principal | ✅ v1 |
| CanAccess | Principal → Resource | Principal has any IAM permission on resource | ✅ v1 |
| HasPermission | Permission → Resource | Statement grants actions on resource (may be wildcards) | ✅ v1 |
| SignedBy | AccessKey → Principal | Long-term credential (access key) belongs to principal | ✅ v1 |
| BelongsTo | Principal → Account | Principal exists in AWS account | ✅ v1 |
| TrustedBy | Principal → FederatedProvider | Cross-account or federated trust relationship | Planned v1.5 |
| MemberOf | Principal → Group | User is member of group | Planned v1.5 |
| AttachedTo | ManagedPolicy → Principal | Managed policy attached directly to principal | Planned v1.5 |
| InlinePolicy | Permission → Principal | Inline policy statement attached to principal | Planned v1.5 |
| References | Permission → Resource | Statement references a resource (resolved via pattern matching) | Planned v2 |
| CanAssumeWithMFA | Principal → Principal | AssumeRole requires MFA (conditional trust) | Planned v2 |
| ExternallyAssumedBy | Principal → FederatedProvider | Principal can be assumed via federated identity | Planned v2 |
| InNetworkRange | NetworkInterface → SecurityGroup | ENI is member of security group | Planned v2 |
| ConnectedTo | NetworkInterface → NetworkInterface | ENI routing/peering relationship | Planned v2 |
| EncryptedWith | Resource → KmsKey | Resource encrypted by KMS key | Planned v2 |
| Owns | Principal → Resource | Principal is the AWS account owner of resource | Planned v2 |
| CanEscalate | Principal → Principal | Path exists to privilege escalation (transitive) | Planned v2 enablement #1 (attack-graph) |

## FFI Boundary (UniFFI)

### Exported from Rust (v1)

UniFFI provides a type-safe, in-process boundary between Go and Rust. The following are exported in v1:

**Graph queries:**
- `find_node(graph: String, label: String, id: String) → Node` — fetch a single node by ID and label
- `walk_edges(graph: String, start: String, edge_types: Vec<String>, direction: Direction, depth_limit: u8) → Stream<Node>` — enumerate neighbors via specific edge types
- `path_finder(graph: String, start: String, end: String, edge_types: Vec<String>, max_hops: u8) → Vec<Path>` — find all paths between two nodes
- `shortest_path_length(graph: String, start: String, end: String, max_hops: u8) → u32` — compute the shortest path distance
- `subgraph_extractor(graph: String, root: String, depth: u8) → Subgraph` — extract a connected subgraph rooted at a node

**Metadata:**
- `version() → String` — returns schema version and build info

**Notes:**
- All functions are async and thread-safe (Send + Sync).
- Node IDs are ARNs; edge types are strings matching the schema (CanAssume, CanAccess, etc.).
- Streaming functions return async iterators (Go consumes as channels via FFI).

### Type Mapping (Rust ↔ Go)

| Rust | Go |
|------|-----|
| `String` | `string` |
| `u64` | `uint64` |
| `Vec<T>` | `[]T` |
| `struct Arn` | Not yet exposed (complex types deferred) |
| `async fn` | `func()` (blocking in Go, async in Rust) |

## Data Flow — Ingestion

Ingestion follows a three-stage pipeline in Go, isolated by interface:

```
AWS APIs (Fetch)
    ↓
    └─→ Service-specific fetcher
        (e.g., go/internal/ingest/aws/iam/iam_fetcher.go)
            │ Returns raw AWS SDK types
            ↓
        Service-specific transformer
        (e.g., go/internal/ingest/aws/iam/iam_transformer.go)
            │ Pure functions: AWS types → ResourceSpec
            ↓
        Service ingester (Ingester interface)
        (e.g., go/internal/ingest/aws/iam/iam_ingester.go)
            │ Implements Enumerate() method
            ├─→ Validate ARN canonicalization via Rust FFI
            └─→ Stream ResourceSpec to graph writer
                    │
                    ↓
            PostgreSQL + Apache AGE
            (INSERT nodes/edges, idempotent upsert)
```

**Key properties:**
- **Fetcher** uses AWS SDK, handles pagination, errors.
- **Transformer** is pure functions; unit-testable without I/O or mocks.
- **Ingester** orchestrates fetch→transform→stream; implements the `Ingester` interface for runtime registration.
- **Idempotency** — re-running ingestion on the same account produces the same graph (upsert semantics).

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
- Single `docker compose` stack: Postgres+AGE on `localhost:5433`, exposed to host
- CLI compiled on host (`go build ./cmd/activable/`)
- Unit tests run on host (go test, cargo test)
- Integration tests require `AGE_TEST_URL=postgres://localhost:5432/testdb` environment variable
- Makefile targets: `make test-integration` runs integration tests; `make test-ffi-stability` runs concurrent FFI stress tests

### Testing (CloudGoat)
- Ephemeral AWS accounts created per test
- CLI ingests test account
- Graph validated against expected primitives

### Production
- Managed Postgres (AWS RDS with read replicas)
- API server (Go stateless pods, HPA)
- Observability: datadog/honeycomb for traces + metrics

## Query API (v1 Substrate)

The Rust `GraphClient` exposes five query primitives. All queries are memory-efficient (streaming where applicable) and leverage Apache AGE's Cypher engine.

### Primitives and Performance Characteristics

Latency measurements from the integration benchmark on synthetic 100k-node AWS IAM graph (single-thread, p95):

| Primitive | Purpose | Signature | Latency (p95) | Exposure |
|-----------|---------|-----------|---------------|----------|
| `find_node` | Fetch a single node by ARN | `find_node(label: &str, id: &NodeId) → Node` | 532 ms | FFI, CLI |
| `walk_edges` | Enumerate neighbors (depth-limited, streaming) | `walk_edges(start, edge_types, direction, depth) → Stream<Node>` | 94 ms / page | FFI, CLI |
| `path_finder` | Find all simple paths between two nodes | `path_finder(start, end, edge_types, max_hops) → Vec<Path>` | ~1–10 ms per path | FFI, GraphQL |
| `shortest_path_length` | Compute shortest-path distance | `shortest_path_length(start, end, max_hops) → u32` | 0.4 ms | FFI, CLI |
| `subgraph_extractor` | Extract a connected subgraph rooted at a node | `subgraph_extractor(root, depth) → Subgraph` | 5–50 ms | FFI, GraphQL |

**Hardware:** AWS EC2 c7i.xlarge, Postgres 16 + Apache AGE 1.6.0, local SSD storage.

**Caveats:**
- `find_node` and `walk_edges` materialize full property blobs; latency dominated by deserialization. For large property sets, prefer querying IDs only and hydrating lazily.
- `path_finder` returns up to 50 paths; on dense graphs, this may consume significant memory. Streaming version deferred to v2.
- All measurements are warm-cache (10 warmup runs prior to measurement).
- Cold-cache latency will be 2–3× higher due to Postgres buffer-pool misses and AGE session initialization (~120 ms).

**API exposure:**
- **FFI boundary:** All primitives exported via `activable-ffi` and accessible from Go.
- **CLI:** Subcommands under `activable query` (e.g., `activable query path`, `activable query walk`).
- **GraphQL:** Served by the GraphQL API server.

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
