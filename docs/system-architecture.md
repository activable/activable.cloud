# System Architecture

Activable is a SaaS knowledge graph platform for cloud infrastructure. This document
describes the v1 substrate: a pure-Rust workspace serving a typed cloud knowledge graph
over GraphQL, backed by Postgres + Apache AGE, with AWS ingestion and IAM risk reasoning,
deployed on Kubernetes. See [`docs/platform.md`](./platform.md) for the full platform
thesis and enablement roadmap.

The stack is **all Rust** — there is no Go layer and no FFI boundary. Seven workspace
crates compile into a single server binary (`activable-graphql`) plus their libraries.
Ingestion is triggered through a GraphQL mutation and executed by a Postgres-backed job
scheduler; there is no standalone CLI in v1.

## Component Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│ activable-graphql  — the only binary (axum + async-graphql server)     │
│   • GraphQL schema + resolvers (queries, mutations)                    │
│   • embeds the scheduler worker pool + ingestion runtime               │
└───────────────┬────────────────────────────────────────────────────────┘
                │ in-process Rust calls (no FFI)
   ┌────────────┼───────────────┬───────────────────┬────────────────────┐
   ↓            ↓               ↓                   ↓                    ↓
┌─────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────────┐ ┌──────────┐
│activable│ │activable-    │ │activable-    │ │activable-iam-    │ │activable-│
│-ingest  │ │scheduler     │ │risk          │ │engine            │ │graph     │
│         │ │              │ │              │ │                  │ │          │
│YAML     │ │Postgres job  │ │5 topology    │ │Parliament-       │ │PG+AGE    │
│engine + │ │queue (FOR    │ │signals +     │ │equivalent IAM    │ │driver,   │
│native   │ │UPDATE SKIP   │ │rule boost,   │ │evaluator: allow/ │ │typed     │
│AWS      │ │LOCKED, dedup,│ │cascade       │ │deny, boundaries, │ │Cypher    │
│enrichers│ │heartbeat     │ │scoring       │ │SCP, conditions,  │ │builder,  │
│         │ │reaper)       │ │              │ │escalation deriv. │ │loaders   │
└────┬────┘ └──────────────┘ └──────────────┘ └──────────────────┘ └────┬─────┘
     │ AWS SDK (fetch + enrich)                                          │
     ↓                                              SQL (Cypher via AGE) ↓
┌──────────────┐                              ┌──────────────────────────────────┐
│ AWS APIs     │                              │ Postgres 16 + Apache AGE 1.6.0     │
│ (or          │                              │   • Named graph: "cloud"           │
│  LocalStack) │                              │   • 16 node labels, 18 edge types  │
└──────────────┘                              │   • jobs table (scheduler state)   │
                                              └──────────────────────────────────┘

activable-schema (foundation crate, depended on by all of the above):
  node/edge label vocabulary, ARN canonicalizer, typed identifiers.
```

### Workspace crates

| Crate | Role |
|-------|------|
| `activable-schema` | Node/edge label vocabulary, ARN canonicalizer, typed IDs. Foundation crate; no I/O. |
| `activable-graph` | Postgres + Apache AGE driver: connection pool (`deadpool-postgres`), typed Cypher builder, idempotent node/edge loaders, query primitives. |
| `activable-ingest` | AWS ingestion: YAML-driven engine + native SDK enrichers (IAM, EC2, S3, KMS, Secrets Manager, Lambda) that fetch, transform, and write the graph. |
| `activable-iam-engine` | IAM authorization-evaluation engine: allow/deny resolution, permission boundaries, NotAction, conditions, SCP, resource policies, escalation derivation, dangerous-action classification. (Not an ingester — see the crate rename note in the changelog.) |
| `activable-risk` | Risk reasoning: five graph-topology signals plus a rule-boost engine, per-principal scoring and per-account cascade aggregation (harmonic mean). |
| `activable-scheduler` | Generic Postgres-backed job queue: workers claim via `FOR UPDATE SKIP LOCKED`, enqueue deduped via partial-unique-index + `ON CONFLICT`, crashed jobs recovered by a heartbeat reaper. |
| `activable-graphql` | The server binary: `axum` + `async-graphql`. Resolvers delegate to the crates above; embeds the scheduler worker pool and the ingestion runtime. |

## Runtime Topology

### Single cluster (development)

The whole stack runs as Kubernetes resources via the Helm chart in `ops/helm/activable`
(zero Docker Compose for the app path). One deployment, no CLI.

```
                 GraphQL mutation: triggerIngest(provider, regions, accountIds)
                                   │
                                   ↓
┌────────────────────────────────────────────────────────────┐
│ activable-graphql pod (axum + async-graphql)                │
│   • resolver enqueues per-account ingest jobs               │
│   • embedded scheduler workers claim jobs (SKIP LOCKED)     │
│   • each job runs activable-ingest enrichers against AWS    │
│     (LocalStack in dev) and writes nodes/edges via          │
│     activable-graph loaders (idempotent MERGE)              │
└───────────────┬──────────────────────────┬──────────────────┘
                │                           │
                ↓                           ↓
   ┌─────────────────────┐      ┌────────────────────────────┐
   │ LocalStack (dev AWS) │      │ Postgres 16 + Apache AGE    │
   │ Deployment :4566     │      │ StatefulSet :5432           │
   │ iam,sts,s3,ec2,kms,  │      │ graph "cloud" + jobs table  │
   │ lambda,organizations,│      └────────────────────────────┘
   │ cloudformation,      │
   │ secretsmanager       │
   └─────────────────────┘

Ingress: a NodePort (dev, :30080) and a gated Gateway-API HTTPRoute
(Envoy Gateway + mkcert TLS at https://activable.localtest.me) front the
GraphQL endpoint. Queries: riskScore / accountRisks / findings / blastRadius /
pathFinder / walkEdges / findNode / subgraph. Mutations: triggerIngest /
(status read via) ingestStatus / ingestJobs.
```

### Distributed (future)

- **GraphQL/worker pods**: the server binary is stateless apart from the shared Postgres
  job queue; it scales horizontally. Scheduler workers coordinate purely through
  `FOR UPDATE SKIP LOCKED`, so adding replicas adds ingestion throughput without a leader.
- **Postgres + AGE**: managed (RDS) or self-hosted with replicas across AZs.
- **Ingestion cadence**: v1 is on-demand / polling (a mutation enqueues a run). Streaming
  (CloudTrail) is a v2 candidate.
- **Telemetry**: `tracing` + OpenTelemetry export to a central OTLP collector.

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
| 1 | Wrap loading loop in explicit `BEGIN`/`COMMIT`; define failure mode: atomic vs. resumable. | ✅ Resolved (ingestion orchestrates transactional batches) |
| 2 | Pre-flight validate edge endpoints; current INSERT silently inserts zero rows on missing endpoints. | ✅ Resolved (enrichers validate ARN format; loaders MERGE endpoints so missing nodes are created, not dropped) |
| 3 | Make `BATCH_SIZE` (currently `500`) configurable. | ✅ Resolved (runtime config in `activable-ingest`) |
| 4 | Integrate `deadpool-postgres` connection pool for the loader (currently single `tokio_postgres::Client`). | ✅ Resolved (`GraphPool` uses `deadpool-postgres` with configurable pool size) |
| 5 | Document `nextval()` sequence-ID gaps under concurrent load as expected behavior. | ✅ Resolved (documented in code; AGE sequence behavior explained in architecture notes) |
| 6 | Add inline comment for `'"{}"'::agtype` literal syntax. | ✅ Resolved (inline comment carried into the production loader) |
| 7 | Parameterize Cypher UNWIND batches (~50 KB per 500-row batch) if statement-size becomes a hotspot. | ✅ Resolved (runtime batch-size parameter) |
| 8 | Add checkpoint/resume logic OR `ON CONFLICT` / pre-flight dedup if crash-resumability is required. | ✅ Resolved (idempotent re-runs; graph upsert via MERGE, scheduler retries via heartbeat reaper) |

### What this benchmark did NOT cover (revisit later)

- **Cold-cache latency.** All measurements are warm-cache.
- **Real AWS data shape.** Synthetic generator approximates fanout/cross-account distributions; real Organizations data may differ.
- **Storage growth.** Did not measure disk footprint at 1M+ edges; production schema work should profile.
- **Write throughput under sustained ingestion load.** The benchmark measured a one-shot bulk load, not steady-state writes.
- **Schema migrations on a live graph.** The benchmark used `drop_graph() + create_graph()`; production schema work needs online migration patterns.
- **Multi-tenancy isolation.** The benchmark used a single `cloud` named graph; multi-tenancy will need per-customer graphs or schemas.

## Graph Schema

The typed vocabulary lives in `activable-schema` (`NodeLabel` / `EdgeType` enums). Both
enums carry a `Custom(String)` escape hatch so ingestion can emit a label outside the v1
set without a schema change, but the canonical typed set is below. Node identity is the
canonical ARN (or a derived deterministic ID for synthetic nodes such as permissions).

### Node labels (16)

| Label | Meaning |
|-------|---------|
| `Principal` | IAM user, role, or cross-account/root principal |
| `Resource` | Generic AWS resource (EC2 instance, Lambda function, etc.) |
| `Permission` | Statement-level effective permission (action + resource + effect) |
| `Account` | AWS account |
| `Vpc` | Virtual private cloud |
| `IamGroup` | IAM group |
| `KmsKey` | KMS key (customer-managed or the AWS-managed sentinel) |
| `AccessKey` | Long-term access-key credential |
| `FederatedProvider` | SAML/OIDC identity provider |
| `PolicyStatement` | Individual policy statement node |
| `PermissionBoundary` | IAM permission-boundary policy |
| `ServiceControlPolicy` | Organizations SCP |
| `Bucket` | S3 bucket |
| `Policy` | Managed or inline policy |
| `WildcardPrincipal` | Sentinel for `Principal: "*"` in a resource policy |
| `Secret` | Secrets Manager secret |

### Edge types (18)

| Edge | Typical direction | Meaning |
|------|-------------------|---------|
| `CanAssume` | Principal → Principal | Role assumable via `sts:AssumeRole` |
| `HasPermission` | Principal/Policy → Resource | Statement grants actions on a resource |
| `HasEffectivePermission` | Principal → Permission | Materialized effective permission after evaluation |
| `Contains` | Account/container → member | Containment (account contains principals, etc.) |
| `MemberOf` | Principal → IamGroup | Group membership |
| `SignedBy` | AccessKey → Principal | Credential belongs to a principal |
| `BoundedBy` | Principal → PermissionBoundary | Permission boundary applied to a principal |
| `GovernedBy` | Account/OU → ServiceControlPolicy | SCP governance |
| `EnforcesScp` | ServiceControlPolicy → target | SCP enforcement relationship |
| `CanEscalateTo` | Principal → Principal | Derived privilege-escalation edge |
| `HasManagedPolicy` | Principal → Policy | Managed policy attachment |
| `HasPermissionsBoundary` | Principal → Policy | Boundary policy attachment |
| `HasBucketPolicy` | Bucket → Policy | S3 bucket resource policy |
| `HasKeyPolicy` | KmsKey → Policy | KMS key policy |
| `AllowsAccessFrom` | Resource/Secret/Bucket → Principal | Resource policy grants access to a principal (incl. external/cross-account) |
| `KmsGrantable` | Principal → KmsKey | Principal can create KMS grants |
| `EncryptedBy` | Secret/Resource → KmsKey | Encryption relationship |
| `ActsOn` | Permission → Secret/Resource | Permission targets a specific resource (links the evaluated permission to its object) |

Which edges appear in a given graph depends on which enrichers ran. The current native
enrichers (IAM, EC2, S3, KMS, Secrets Manager, Lambda) emit `CanAssume`,
`HasEffectivePermission`, `MemberOf`, `AllowsAccessFrom`, `EncryptedBy`, `ActsOn`,
`HasBucketPolicy`, `HasKeyPolicy`, and the boundary/SCP edges; `CanEscalateTo` is derived
by `activable-iam-engine`.

## Data Flow — Ingestion

Ingestion is a GraphQL-triggered, scheduler-driven pipeline — entirely in-process Rust,
no CLI and no language boundary:

```
GraphQL: triggerIngest(provider: "aws", regions, accountIds)
    ↓
activable-graphql resolver enqueues one job per account
    (activable-scheduler: INSERT ... ON CONFLICT dedup)
    ↓
scheduler worker claims a job (UPDATE ... FOR UPDATE SKIP LOCKED)
    ↓
activable-ingest runtime runs the enricher set for the account:
    fetch (AWS SDK, paginated)  →  transform (pure fns: SDK types → graph rows)
    →  load (activable-graph idempotent MERGE of nodes + edges)
    ↓
relationship rules (config-driven joins) materialize derived edges
    ↓
graph "cloud" in Postgres + Apache AGE
    ↓
job marked completed; heartbeat reaper recovers any crashed worker's job
```

**Key properties:**
- **Fetch** uses the AWS SDK, handles pagination and per-service errors (fail-soft: one
  enricher's error does not abort the others).
- **Transform** is pure functions over SDK types; unit-testable without I/O.
- **Load** is idempotent — re-running ingestion on the same account converges to the same
  graph (MERGE on identifying keys).
- **At-least-once with idempotent writes**: the scheduler may retry a crashed job; the
  idempotent loaders make that safe.

## Concurrency Model

- **Async runtime**: `tokio` across the workspace.
- **Scheduler**: multiple worker tasks (and, in production, multiple pods) claim jobs with
  `FOR UPDATE SKIP LOCKED` — no leader election, no double-claim. Enqueue dedup is a
  partial unique index + `ON CONFLICT DO NOTHING`. A heartbeat column + reaper re-queues
  jobs whose worker died.
- **Connection pooling**: `deadpool-postgres`; AGE session setup (`LOAD 'age'; SET
  search_path`) is amortized across pooled checkouts.
- **Ingestion**: enrichers run concurrently within a job; writes are batched.

## Telemetry

`tracing` instrumentation with OpenTelemetry export:

```
activable-graphql
  ├─→ span: graphql_request
  │     └─→ span: trigger_ingest → enqueue jobs
  ├─→ span: ingest_account (per scheduler job)
  │     ├─→ span: enrich_iam / enrich_s3 / enrich_kms / ...
  │     └─→ span: graph_write (batched MERGE)
  └─→ metrics: ingest duration, nodes/edges written, per-enricher errors
        └─→ export to OTLP collector (gRPC)
```

## Deployment Targets

### Development (local Kubernetes)

- Helm chart `ops/helm/activable` deploys Postgres+AGE (StatefulSet), LocalStack
  (Deployment), and the `activable-graphql` server. `make dev-up` builds the image
  (`ops/docker/Dockerfile`, a cross-compiled linux binary copied in) and installs the chart.
- The server binary is built with `cargo zigbuild --target aarch64-unknown-linux-gnu` on
  Apple-silicon hosts (`make build-linux`).
- Integration tests that need a live graph are gated on `AGE_TEST_URL`; the scripted E2E
  harness lives under `tests/e2e/` and drives the deployed GraphQL endpoint.

### Production

- Managed Postgres (RDS) with read replicas; the `cloud` graph (or per-tenant graphs).
- Stateless `activable-graphql` pods behind a Gateway-API gateway with TLS; horizontal
  scaling backed by the shared Postgres job queue.
- Observability: OTLP traces + metrics to the platform collector.

## Query API (v1 substrate)

`activable-graph::GraphClient` exposes the graph query primitives; `activable-graphql`
resolvers call them directly (in-process — no FFI, no CLI). Latency figures are from the
benchmark on a synthetic 100k-node AWS IAM graph (single-thread, warm-cache p95).

| Primitive | Purpose | Latency (p95) | GraphQL field |
|-----------|---------|---------------|---------------|
| `find_node` | Fetch a single node by label + ARN | 532 ms | `findNode` |
| `walk_edges` | Enumerate one-hop neighbors, result-limited, streaming, optional edge-type filter | 94 ms / page | `walkEdges` |
| `path_finder` | Find simple paths between two nodes (single edge type per call) | ~1–10 ms / path | `pathFinder` |
| `shortest_path_length` | Shortest-path distance | 0.4 ms | (internal) |
| `blast_radius` / `subgraph` | Collect the reachable neighborhood of a node | 5–50 ms | `blastRadius` / `subgraph` |

On top of the graph primitives, `activable-risk` powers the risk queries
(`riskScore`, `accountRisks`, `findings`) and `activable-scheduler` backs the ingestion
fields (`triggerIngest`, `ingestStatus`, `ingestJobs`).

**Hardware:** AWS EC2 c7i.xlarge, Postgres 16 + Apache AGE 1.6.0, local SSD storage.

**Caveats:**
- `find_node` and `walk_edges` materialize full property blobs; latency is dominated by
  deserialization. For large property sets, prefer querying IDs only and hydrating lazily.
- `path_finder` returns up to 50 paths; on dense graphs this can consume significant
  memory. A streaming version is deferred.
- AGE has no edge-label alternation (`[r:A|B]` is a syntax error) and treats a bare
  identifier in a variable-length pattern as a variable binding, not a type filter.
  Multi-edge-type single-hop walks therefore filter via `WHERE label(r) IN [...]`, and
  variable-length traversal is restricted to a single colon-typed edge per call.
- All measurements are warm-cache; cold-cache latency is 2–3× higher (Postgres buffer-pool
  misses + ~120 ms AGE session init).

## Security Boundary

### Ingestion IAM role

Least-privilege, read-only — no write actions, no secrets material, no console access:

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
      ],
      "Resource": "*"
    }
  ]
}
```

### Cypher injection surface

All user-supplied values (node IDs/ARNs, edge-type names) that reach a Cypher string flow
through `activable-graph`'s `escape_cypher` / `validate_label`: ARNs are single-quote
escaped, and edge/label names are validated against `[A-Za-z][A-Za-z0-9_]*` before
embedding. This is the primary injection boundary of the API.

### Graph access control

- **Multi-tenancy** (future): separate graphs per customer (Postgres schemas or instances).
- **API auth** (future): authenticated requests with scoped authorization on graph operations.
- **Audit**: `tracing` spans carry request identity.

## Failure Modes & Recovery

| Failure | Detection | Recovery |
|---------|-----------|----------|
| Postgres unavailable | graph write returns an error | scheduler retries the job with backoff; heartbeat reaper re-queues if the worker died mid-job |
| One enricher errors | per-enricher error logged | ingestion continues with the other enrichers (fail-soft); the run records the partial error set |
| Worker crash mid-job | heartbeat goes stale | reaper resets the job to `pending`; idempotent loaders make the retry safe |
| AWS API timeout / throttling | SDK timeout | per-service retry budget |
| Invalid edge type / unsafe parameter | `validate_label` / `escape_cypher` reject it | request returns a client error, not a 500; nothing reaches the database |

---

**Next:** See [Deployment Guide](./deployment-guide.md) for build and runtime setup.
