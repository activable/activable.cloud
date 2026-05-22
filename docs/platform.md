# Activable — Platform overview

> Activable is the cognitive layer for cloud infrastructure. It maintains a canonical
> knowledge graph of a cloud environment — every resource, identity, configuration, and
> relationship — and exposes it as a reasoning substrate through a GraphQL API. Tools
> that need to understand the cloud (security analyzers, drift detectors, cost optimizers,
> IaC synthesizers, AI agents) consume the graph instead of duplicating cloud ingestion.
> The cloud becomes *activable*: queryable, programmable, agent-controllable.

---

## 1. Why a knowledge graph for cloud

Cloud infrastructure is fundamentally relational: IAM roles trust other roles, S3 buckets
contain objects that Lambda functions read under attached execution roles, VPCs contain
subnets that contain instances with security groups that reference other security groups.
Yet the cloud APIs that expose this state are inert — they answer one isolated question at
a time. A call to `iam:GetUser` returns a user record; a call to `s3:GetBucketPolicy`
returns a bucket policy; there is no API that says "what is the complete set of identities
that can reach this object, through any combination of direct permissions, role chains, and
resource policies?"

Every tool that reasons over cloud state hits the same wall:

- **Security analyzers** (attack-path tools, IAM auditors) build a custom ingestion layer
  to reconstruct relationships the APIs do not expose directly.
- **Drift detectors** build their own state snapshot to compare against declared IaC.
- **Cost optimizers** fetch resource inventory independently and annotate it with pricing.
- **AI agents** that interact with cloud APIs re-ingest the same data a fourth time.

Each tool pays the full cost of ingestion independently. The relationships each tool
discovers — "this Lambda can reach this S3 bucket via this execution role" — are computed,
used once, and discarded. The next tool starts from scratch.

A canonical knowledge graph solves this once. Ingest the full cloud state into a typed,
queryable graph with a stable schema. Every tool that needs to reason over the cloud reads
from the graph instead of calling cloud APIs. Relationships are computed once and reused.
New reasoning capabilities — attack-path discovery, drift detection, cost analysis —
become consumers of the same substrate rather than independent re-ingestion systems.

This is the Activable thesis: a shared, canonical knowledge graph for cloud infrastructure,
exposed via a GraphQL API, so the cloud becomes a substrate that reasoning systems can
act on rather than a collection of isolated API endpoints each tool re-invents.

---

## 2. What "activable" means

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
the same graph (see [docs/system-architecture.md](./system-architecture.md) for the
formal schema and [plans/ROADMAP.md](../plans/ROADMAP.md) for the enablement roadmap).

This is also the platform's design thesis: every feature added to Activable should
extend the reasoning power of the graph, not add a new ingestion silo. The name is
a promise about what the platform does to cloud infrastructure.

---

## 3. The schema (high level)

The knowledge graph models cloud state as typed nodes connected by typed edges. The
formal schema definition lives in [docs/system-architecture.md](./system-architecture.md);
what follows is the high-level structure.

### Node categories

| Category | Examples | What they represent |
|---|---|---|
| **Identity** | Principal, ServicePrincipal, FederatedProvider | Who can act: IAM users, roles, service accounts, SAML/OIDC providers |
| **Credential** | AccessKey | Long-lived credentials attached to identities |
| **Authorization** | Permission | IAM policy statements (sid, action, resource) |
| **Resource** | Resource | Cloud resources: S3 buckets, Lambda functions, EC2 instances, etc. |
| **Configuration** | (derived from resource properties) | Settings, tags, security-group rules, bucket policies |
| **Dependency** | (expressed as edges) | Relationships among the above |

### Edge categories

| Edge type | Meaning |
|---|---|
| **CanAssume** | A principal has AssumeRole permission on another principal |
| **CanAccess** | A principal has an IAM action permitted on a resource |
| **Contains** | A permission statement scopes a resource |
| **TrustedBy** | Cross-account trust relationship |
| **SignedBy** | A credential belongs to a principal |
| *(12 more types)* | See [system-architecture.md](./system-architecture.md) |

### Why graph, not relational or document

A relational schema could model entities in tables, but multi-hop queries ("find all
principals that can reach this S3 bucket through any combination of role assumptions and
resource policies") require expensive recursive CTEs or denormalized join tables that
break at production scale. A document store has the same problem: documents are
self-contained and relationships are opaque until the application re-assembles them at
query time.

A property graph lets Cypher express multi-hop traversals as first-class operations. The
graph schema is additive: new node types and edge types extend the schema without
breaking existing queries. This makes it the natural fit for a platform designed to
support many independent reasoning consumers.

---

## 4. The enablement model

The enablement model is how new reasoning capabilities plug into the graph without
duplicating ingestion.

```
                      ┌─────────────────────────┐
  Cloud APIs          │   Ingestion Layer        │
  (AWS, K8s, ...)  ── │   (Go — provider SDKs)  │
                      └───────────┬─────────────┘
                                  │
                                  ▼
                      ┌─────────────────────────┐
                      │  Canonical Knowledge     │
                      │  Graph (Postgres + AGE)  │
                      │  typed nodes + edges     │
                      └───────────┬─────────────┘
                                  │
                      ┌───────────▼─────────────┐
                      │  GraphQL API (Go server) │
                      │  Kubernetes-deployed     │
                      └───────┬──────┬──────┬───┘
                              │      │      │
               ┌──────────────┘      │      └──────────────┐
               ▼                     ▼                      ▼
        Attack-graph           Drift + IaC            FinOps / cost
        (v2 — #1)              (v2+)                  (v2+)
               ▼                     ▼                      ▼
        IAM right-sizing       Agentic action         Security rules
        (v2+)                  layer (v2+)            (v2+)
```

**Ingesters** call cloud provider APIs and write typed nodes and edges into the graph.
There is one ingester per provider (AWS, K8s, eventually Azure and GCP). Ingesters do
not know about use cases — they populate the canonical schema.

**Enablement consumers** read from the graph via the GraphQL API. They do not call cloud
APIs directly. An attack-graph consumer walks `CanAssume` and `CanAccess` edges to find
paths; a drift detector compares graph nodes against declared IaC state; a cost optimizer
annotates resource nodes with pricing data and walks `Contains` edges to find unused
capacity. Each consumer reuses the same ingested data without re-ingesting.

**Read-only consumers** (attack-graph, drift, cost, compliance) query the graph and
produce analysis results. They do not mutate graph state.

**Read-write consumers** (agentic action layer) query the graph, propose mutations to
cloud state (not to the graph directly), and commit changes through gated pipelines that
require human approval. The graph reflects the proposed state only after the cloud API
confirms the change and the next ingestion cycle updates the graph.

This separation — one ingestion layer, many independent reasoning consumers — is the
core architectural decision that makes the platform general rather than a single-purpose
tool.

---

## 5. v1: the substrate

v1 ships the substrate alone. No enablement consumers ship in v1. v1 is the foundation
the enablement consumers require.

### What v1 includes

**Knowledge graph** — Postgres 16 + Apache AGE; canonical schema for cloud entities and
relationships (12 node types, 17 edge types). The graph-backend benchmark validates
Postgres + Apache AGE at 100k nodes with thousands-of-times margin on all traversal
gates. See [docs/system-architecture.md](./system-architecture.md) for the benchmark
methodology and verdict.

**Rust query primitives** — a typed Rust crate (`activable-graph`) with programmatic
query primitives: `findNode`, `walkEdges`, `pathFinder`, `blastRadius`, `subgraph`.
These primitives express the traversal patterns all enablement consumers will need,
tested and stable before any consumer is built.

**GraphQL API server** — a Go server, Kubernetes-deployed, exposing the graph to
external consumers. Query operations map directly to the Rust primitives:

```graphql
# Find all paths from one identity to a resource
query {
  pathFinder(fromId: "arn:aws:iam::123:role/ExampleRole", toId: "arn:aws:s3:::my-bucket") {
    nodes { id type name }
    edges { type fromId toId }
  }
}

# Walk outbound edges from a node
query {
  walkEdges(fromId: "arn:aws:iam::123:user/example", direction: OUTBOUND) {
    nodes { id type }
    edges { type toId }
  }
}

# Blast radius: what can this identity reach?
query {
  blastRadius(fromId: "arn:aws:iam::123:role/BroadRole") {
    nodes { id type name }
  }
}
```

Mutation operations cover ingestion control:

```graphql
# Trigger an ingestion run; returns a job ID to poll
mutation {
  triggerIngest(provider: AWS, regions: ["us-east-1", "us-west-2"]) {
    jobId
    status
  }
}

# Poll ingestion status
query {
  ingestStatus(jobId: "job-abc123") {
    status
    startedAt
    completedAt
    errors { message resourceId }
  }
}
```

**AWS ingestion** — canonical first ingester. Fetches IAM (users, roles, policies,
groups, SAML/OIDC providers), S3, Lambda, EC2, and more via `aws-sdk-go-v2`; transforms
to typed nodes and edges; writes to the graph. Triggered via `triggerIngest` mutation or
on a scheduled cadence.

**Kubernetes deployment** — Kind/k3d for local development, Helm chart for production.
Docker Compose is retained only as a fallback for starting the Postgres + AGE database
in isolation. The full stack (graph database + GraphQL API server + ingestion workers)
runs on Kubernetes.

### What v1 does not include

- No use-case-specific reasoning: no attack-path discovery, no drift detection, no cost
  analysis, no compliance rules. Those are enablement consumers; they ship after the
  substrate is stable.
- No Parliament IAM policy evaluator. IAM-aware reasoning (evaluating policy conditions,
  simulating assume-role chains) is part of the cloud attack-graph enablement, not the
  substrate.
- No agentic purple-team loop. The agentic layer requires a stable query substrate and
  an attack-graph consumer to be useful.
- No multi-cloud ingestion. v1 ingests AWS. K8s ingestion is v1 unless explicitly
  deferred to the next release.

A reader who previously encountered Activable as "the cloud attack-graph platform" should
understand the resequencing here: attack-graph is the first thing built on top of the
substrate, not the substrate itself. The substrate ships first because it is the
foundation every use case requires, and building it without the weight of a specific
use-case implementation produces a cleaner, more general foundation.

---

## 6. Enablement consumers (v2+ design targets, not yet implemented)

The following consumers are designed to run on the v1 substrate. None is committed or
implemented. They are described here to demonstrate that the v1 schema is general enough
to support each one without schema changes or re-ingestion.

---

### Cloud attack-graph

*Design target, not yet implemented.*

The most researched enablement. Cross-domain attack-path discovery across AWS and K8s,
using Cypher patterns that walk `CanAssume`, `CanAccess`, `Contains`, and bridge edges
between IAM roles and K8s service accounts.

Components:
- **Parliament-equivalent IAM evaluator** (`activable-iam-eval`) — offline Rust crate
  that evaluates IAM policy documents against a principal and resource, producing
  allow/deny decisions without calling `iam:SimulatePrincipalPolicy`. Port of the Python
  Parliament library to Rust with full condition-key support.
- **Attack-path engine** — Cypher-based path-finder that applies IAM eval to filter
  traversal results to actually-reachable paths.
- **Agentic purple-team layer** — LangGraph-based agent loop: hypothesis generation
  (what attack scenarios are worth exploring), path explanation (natural-language
  description of a found path), and CTI re-ranking (prioritizing paths against known
  threat-intelligence patterns).

The v1 graph schema and `pathFinder`/`blastRadius` query primitives are designed with
this consumer in mind. When this enablement ships, it consumes the substrate via the
GraphQL API.

---

### Drift detection + cloud-as-code reverse engineering

*Design target, not yet implemented.*

Walk declared IaC (Terraform state files, CloudFormation templates, Pulumi stack
exports); walk the live graph; surface diffs as typed events. Every drift event
references the graph nodes involved, so downstream consumers (alerting, remediation
suggestions) can act on structured data rather than text diffs.

Reverse direction: synthesize Terraform or Pulumi modules from current graph state.
Useful for teams that inherit undocumented infrastructure and need IaC coverage.

---

### Cost / FinOps reasoning

*Design target, not yet implemented.*

Annotate graph edges and resource nodes with cost data (from AWS Cost Explorer or
equivalent billing APIs). Walk `Contains` and `CanAccess` edges to surface idle
resources, expensive trust chains, and over-provisioned scaling groups.

Path-aware spend analysis becomes tractable once the graph exists: "which IAM role
chains lead to resources with no recent access events and significant monthly cost" is a
graph traversal, not a multi-table SQL join.

---

### IAM right-sizing / least-privilege synthesis

*Design target, not yet implemented.*

Inverse of the attack-graph enablement: where attack-graph finds what a principal *can*
do, IAM right-sizing maps what a principal *does* do (from access logs and CloudTrail
events correlated with graph state) and recommends a minimal policy granting only
observed accesses.

Output: ready-to-apply IAM policy JSON diffs, referenced to the affected nodes in the
graph so the operator can review the context before applying.

---

### Agentic action layer

*Design target, not yet implemented.*

Typed tool surface (MCP-style) that exposes the graph to LLM agents: query operations
(the same GraphQL queries described in §5), proposed mutation operations (suggest a
policy change, suggest a resource tag), and (eventually) committed operations through
gated approval pipelines.

Closes the loop from "agents read the graph" to "agents act on the cloud" without
bypassing human approval gates for consequential changes.

---

### Security-rule synthesis

*Design target, not yet implemented.*

Generate Sigma, Splunk SPL, and CrowdStrike detection rules from validated attack paths.
A path in the attack-graph that represents a known attacker technique maps to a
detection rule that fires when CloudTrail records the API calls that path would generate.

Output: ready-to-deploy rule packs, with path provenance so the detection engineer can
audit the reasoning behind each rule.

---

### Multi-cloud (Azure + GCP)

*Design target, not yet implemented.*

Extend ingestion to Azure and GCP behind the same canonical schema. The graph schema
uses ARN-style canonical identifiers as a node ID convention; extending to Azure resource
IDs and GCP resource names requires ingester work and minor schema extensions (new node
and edge types for Azure/GCP-specific concepts), but the query layer and all existing
consumers continue to work unchanged.

Cross-cloud reasoning (identity federation paths spanning AWS + Azure, shared resources
accessible from multiple cloud environments) becomes a graph traversal once the schema
covers multiple providers.
