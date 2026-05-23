# Adversarial E2E Validation Report

**Date:** 2026-05-24
**Environment:** Floci (localhost:4566) + Postgres+AGE (localhost:5433)
**Branch:** feat/skyeye-phase-01
**Server:** `target/release/activable-graphql` (PID 63664, port 8080)

---

## Executive Summary

**Result: PARTIAL — Nodes ingested, edges missing. Scoring pipeline blocked.**

The platform ingests IAM principals from Floci into the graph (9 nodes created),
but does not create policy edges (HasEffectivePermission, CanEscalateTo). Risk
scoring requires these edges and cannot produce scores without them.

---

## Infrastructure ✅

| Component | Status | Detail |
|-----------|--------|--------|
| Postgres+AGE | ✅ Running | localhost:5433, `activable` database |
| AGE graph | ✅ Created | `cloud` graph, verified via `ag_catalog.ag_graph` |
| Floci | ✅ Running | localhost:4566, IAM + S3 + STS + EC2 working |
| GraphQL server | ✅ Running | localhost:8080, health check passes |
| IngestRuntime | ✅ Initialized | 10 resource types loaded |
| GraphClientAdapter | ✅ Connected | Wrapping real GraphClient to PG+AGE |
| RiskConfig | ✅ Loaded | blast_radius=0.20, path_to_admin=0.25, dangerous_actions=0.15 |

## Adversarial IAM Seeding ✅

6 roles created in Floci via AWS CLI:

| Role | Scenario | Key permissions |
|------|----------|----------------|
| developer-role | 1: CF Trap | cloudformation:CreateStack, iam:PassRole, sts:AssumeRole |
| cf-deploy-role | 1: CF Trap | iam:CreateRole, iam:AttachRolePolicy, iam:PassRole, lambda:CreateFunction |
| github-actions-role | 2: OIDC | Federated OIDC trust (repo:myorg/*:*), iam:AttachRolePolicy |
| dev-infra-role | 3: S3 OrgID | s3:GetObject, s3:PutBucketPolicy |
| app-role | 4: KMS | kms:Decrypt (scoped to specific key) |
| kms-admin-role | 4: KMS | kms:* (wildcard) |

Verified: `aws --endpoint-url http://localhost:4566 iam list-roles` returns all 6.

## Ingestion Results

### triggerIngest mutation ✅
```json
{"data":{"triggerIngest":{"id":"run-1779561120232958000","status":"RUNNING"}}}
```

### Graph nodes ✅ (9 nodes written)
```sql
SELECT labels(n), n.id FROM cypher('cloud', $$ MATCH (n) RETURN labels(n), n.id $$);

 ["Principal"]     | "arn:aws:iam::000000000000:role/developer-role"
 ["Principal"]     | "arn:aws:iam::000000000000:role/cf-deploy-role"
 ["Principal"]     | "arn:aws:iam::000000000000:role/github-actions-role"
 ["Principal"]     | "arn:aws:iam::000000000000:role/dev-infra-role"
 ["Principal"]     | "arn:aws:iam::000000000000:role/app-role"
 ["Principal"]     | "arn:aws:iam::000000000000:role/kms-admin-role"
 ["Account"]       | "000000000000"
 ["Vpc"]           | "vpc-default"
 ["SecurityGroup"] | "sg-default"
```

**Finding:** Native SDK fallback triggered correctly after CCAPI returned empty.
6 Principal nodes + 1 Account + 1 VPC + 1 SecurityGroup = 9 nodes total.

### Graph edges ❌ (0 edges)
```sql
SELECT type(r), count(*) FROM cypher('cloud', $$ MATCH ()-[r]->() RETURN type(r), count(*) $$);
-- (0 rows)
```

**Root cause:** The native SDK fallback creates Principal nodes from `list_roles`
but does NOT:
1. Fetch each role's inline policies (`get_role_policy`)
2. Parse policies into effective permissions
3. Create HasEffectivePermission edges
4. Run escalation derivation (CanEscalateTo edges)
5. Run relationship inference engine

The enrichment step (native/iam.rs, native/s3.rs, native/ec2.rs) and relationship
engine (relationship.rs) depend on node properties that the native SDK fallback
doesn't populate.

## Risk Scoring ❌

### riskScore query
```json
{"errors":[{"message":"Failed to read risk assessment"}]}
```
**Cause:** No `risk_assessment_json` property on nodes (hasn't been scored).

### refreshRiskScore mutation
```json
{"errors":[{"message":"Failed to retrieve principal permissions"}]}
```
**Cause:** `get_effective_permissions()` queries `HasEffectivePermission` edges which
don't exist (0 edges in graph).

### findings query
```json
{"errors":[{"message":"Failed to list principals"}]}
```
**Cause:** `list_principal_ids()` Cypher query fails because graph node property
format doesn't match query expectation.

## Detection Pipeline Gap Analysis

```
Floci (6 roles with policies)
  ↓ [CCAPI: empty — Floci doesn't support CloudControl]
  ↓ [Native SDK fallback: list_roles → 6 Principal nodes created ✅]
  ↓ [BUT: no policy properties stored on nodes]
  ↓ [Enrichers: can't enrich without policy properties]
  ↓ [Relationship engine: can't infer without properties]
  ↓
Graph: 9 nodes, 0 edges
  ↓
Risk scoring: "no permissions found" — cannot compute signals
  ↓
Detection: BLOCKED
```

### What needs to be fixed (in priority order)

1. **P0: Native SDK fallback must fetch role policies**
   - After `list_roles()`, call `list_role_policies()` + `get_role_policy()` for each role
   - Store policy JSON as node property (same format as CCAPI would)
   - This enables the enricher + relationship engine to run

2. **P1: Enrichers must run after native SDK fallback**
   - IAM enricher: parse trust policies → CanAssume edges
   - Parse inline policies → HasEffectivePermission edges
   - Currently only runs after CCAPI path, not fallback path

3. **P2: GraphClientAdapter.list_principal_ids() Cypher query**
   - Must handle AGE's node label format correctly
   - Currently returns error instead of node IDs

## What IS proven (honest)

| Capability | Proven? | Evidence |
|-----------|---------|---------|
| Server compiles + runs | ✅ | Binary starts, health check passes |
| Floci connectivity | ✅ | 6 IAM roles created + verified |
| PG+AGE graph writes | ✅ | 9 nodes written to AGE graph |
| Native SDK fallback triggers | ✅ | CCAPI empty → fallback fired → nodes created |
| GraphQL mutations work | ✅ | triggerIngest returns run ID |
| GraphQL queries work | ✅ | ingestStatus returns service breakdown |
| Risk scoring pipeline | ❌ | Blocked by missing edges |
| Escalation detection | ❌ | Blocked by missing edges |
| Cross-account evaluation | ❌ | Blocked by missing edges |

## Next steps

**The platform is 60% of the way to a real E2E scan.** Nodes are in the graph.
The remaining 40% is populating edges (policy → permission → escalation chain).

Fix the native SDK fallback to fetch + store role policies → enrichers create edges
→ risk scoring produces real scores → detection validates against adversarial scenarios.

This is honest engineering work, not a plan or a test — it's a real infrastructure
gap that needs code changes in `crates/activable-ingest/src/native_fallback.rs`.
