---
title: "Adversarial scenario execution — Floci + real AWS"
description: "Execute 5 realistic privilege escalation attack chains against SkyEye platform to validate detection coverage across multi-account, OIDC, resource policy, and KMS vectors."
status: pending
priority: P1
effort: 8d
branch: feat/skyeye-phase-01
tags: [validation, adversarial, floci, aws-integration, risk-scoring]
created: 2026-05-24
---

# Adversarial Scenario Execution Plan

## Overview

Execute 5 realistic privilege escalation scenarios against the SkyEye platform (activable-ingest, activable-ingest-iam, activable-risk, activable-graphql) to validate detection capabilities. Each scenario defines:

- Exact IAM policies (identity, resource, trust) to deploy
- Attack chains where individual permissions are innocent but combinations are dangerous
- Platform detection functions expected to fire
- GraphQL queries to validate detection
- Expected risk scores and signals

**Parent plan:** `plans/260524-1400-skyeye-full-coverage/`
**Scenarios source:** `plans/260524-1400-skyeye-full-coverage/adversarial-validation-scenarios.md`

---

## Key Context

### Platform Targets
- `activable-ingest` — AWS IAM ingestion (CloudTrail, policy enumeration)
- `activable-ingest-iam` — IAM policy evaluation, resource policies, federation analysis
- `activable-risk` — Privilege escalation detection, risk scoring, blast radius calculation
- `activable-graphql` — Risk API with queries: `riskScore()`, `findings()`, `refreshRiskScore()`

### Deployment Architecture: Kubernetes (NOT docker-compose)

The platform runs on Kubernetes. E2E validation MUST use K8s to prove the production architecture.

**Local K8s cluster:**
```bash
kind create cluster --name activable   # or k3d cluster create activable
helm install activable ./deploy/helm/activable \
  --set floci.enabled=true \
  --set database.host=postgres-service
```

**Services in K8s:**
- `activable-api` — GraphQL server (Deployment + Service)
- `activable-floci` — Floci AWS mock (Deployment + Service, port 4566)
- `activable-db` — Postgres+AGE (StatefulSet + Service, port 5432)

**Access:**
```bash
kubectl port-forward svc/activable-api 8080:8080      # GraphQL API
kubectl port-forward svc/activable-floci 4566:4566     # Floci (for seeding)
```

**Seed adversarial scenarios:**
```bash
aws --endpoint-url http://localhost:4566 iam create-role ...   # via port-forward to Floci
```

**Trigger ingestion + query results:**
```bash
curl http://localhost:8080/graphql -d '{"query":"mutation { triggerIngest(...) }"}'
curl http://localhost:8080/graphql -d '{"query":"{ riskScore(principalId: \"...\") { score severity } }"}'
```

**Teardown:**
```bash
helm uninstall activable
kind delete cluster --name activable
```

### Test Environments

1. **Kind/k3d cluster (primary)** — local K8s, Helm-deployed stack, Floci as service
   - All 5 scenarios seeded into Floci service
   - Full production architecture: K8s networking, service discovery, health checks
   - Repeatable: `helm uninstall && helm install` for clean state

2. **Real AWS accounts (validation)** — 3+ accounts for production-grade proof
   - Account IDs: dev=`111111111111`, staging=`222222222222`, prod=`333333333333`
   - Deploy via CloudFormation StackSets
   - Teardown via `aws-nuke` with whitelist + dry-run gate

### Key Artifacts
- Helm chart: `deploy/helm/activable/` (production deployment)
- Helm values for Floci: `deploy/helm/activable/values.yaml` (`floci.enabled: true`)
- Seed scripts: `infra/scripts/seed-adversarial-scenarios.sh`
- Results matrix: `plans/reports/adversarial-validation-results-YYYYMMDD.md`

---

## Phases at a Glance

| Phase | Title | Duration | Blocker | Output |
|-------|-------|----------|---------|--------|
| 0 | Pre-flight: Floci multi-account validation | 0.25d | Docker setup | Decision: use Floci or fallback to real AWS |
| 1 | Floci seed scripts | 2d | Phase 0 | 5 seed functions in `seed-floci.sh` |
| 2 | Pipeline ingestion run | 1d | Phase 1 | Populated graph for each scenario |
| 3 | Scenario 1: CF trap | 1d | Phase 2 | Validates `detect_dangerous_actions()` + CF escalation |
| 4 | Scenario 2: OIDC drift | 1d | Phase 2 | Validates federation drift detection |
| 5 | Scenario 3: S3 OrgID | 1d | Phase 2 | Validates resource policy boundary eval |
| 6 | Scenario 4: KMS grant | 1d | Phase 2 | Validates grant-based escalation |
| 7 | Scenario 5: full chain | 1d | Phase 2 | Validates multi-vector aggregation |
| 8 | Results report + teardown | 0.5d | Phases 3-7 | Coverage matrix, results markdown, cleanup |

**Critical path:** Phase 0 → Phase 1 → Phase 2 → Phases 3-7 (parallel) → Phase 8

---

## Detailed Phase Descriptions

### Phase 0: Pre-flight Floci Multi-Account Validation (0.25d)
**Test whether Floci actually supports multi-account isolation before investing time in seed scripts.**

**Critical Pre-Flight Test:**

Start Floci and verify account isolation works:

```bash
# Start Floci
docker compose -f infra/compose/docker-compose.dev.yml up -d floci
sleep 5

# Create role in "account A"
AWS_ACCESS_KEY_ID=111111111111 AWS_SECRET_ACCESS_KEY=test \
  aws --endpoint-url http://localhost:4566 iam create-role \
    --role-name test-isolation \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'

# Check from "account B" — should NOT see test-isolation
AWS_ACCESS_KEY_ID=222222222222 AWS_SECRET_ACCESS_KEY=test \
  aws --endpoint-url http://localhost:4566 iam list-roles

# If test-isolation appears → Floci does NOT isolate accounts
# If test-isolation does NOT appear → Floci isolation works, proceed with Floci
```

**Decision Logic:**

- **Floci isolation WORKS:** Proceed with Phase 1 (seed all scenarios on Floci)
- **Floci isolation FAILS:** Apply fallback plan:
  - Cross-account scenarios (1, 2, 4, 5): deploy to real AWS test accounts via CloudFormation
  - Single-account scenarios (3): keep on Floci
  - Update Phase 1 seed scripts to support both Floci and real AWS deployment targets

**Success criteria:**
- [ ] Floci starts and responds on port 4566
- [ ] Account isolation test PASSES (role in account A not visible from account B)
- [ ] Decision documented: "Using Floci for all scenarios" OR "Using Floci + real AWS (fallback)"

### Phase 1: Floci Seed Scripts (2d)
**Extend `/infra/scripts/seed-floci.sh`** with 5 scenario-specific seed functions.

**Deliverables:**
- `seed_scenario_1_cf_trap()` — Creates dev + staging accounts, CF deploy role, developer role, cross-account trust
- `seed_scenario_2_oidc_drift()` — Creates GitHub OIDC provider, drifted trust policy (v1 then v2), CodePipeline roles
- `seed_scenario_3_s3_orgid()` — Creates dev bucket with `s3:PutBucketPolicy`, shared data bucket with org-ID condition
- `seed_scenario_4_kms_grant()` — Creates KMS key with grant permissions, application role, infrastructure role
- `seed_scenario_5_full_chain()` — Combines all above in one environment, with multi-account simulation via `AWS_ACCESS_KEY_ID`

**Success criteria:**
- [ ] Each seed function creates its exact IAM configuration (policies, roles, trusts, buckets)
- [ ] Multi-account simulation via different `AWS_ACCESS_KEY_ID` per account (e.g., `111111111111` for dev)
- [ ] Verify: `aws iam list-roles` returns expected roles for each scenario
- [ ] Verify: `aws s3api get-bucket-policy` returns exact policies from scenarios doc
- [ ] Verify: `aws kms describe-key` returns expected key with proper grants
- [ ] No errors on repeated seed function calls (idempotent)

### Phase 2: Pipeline Ingestion Run (1d)
**Start Floci + Postgres+AGE, seed each scenario, trigger ingestion, verify graph population.**

**Steps:**
1. Start docker-compose (Floci on 4566, Postgres+AGE on standard ports)
2. For each scenario 1-5:
   a. Call seed function from Phase 1
   b. Run `triggerIngest` GraphQL mutation
   c. Wait for ingestion to complete
   d. Query: `principalRisks()` or `accountRisks()` to confirm graph populated
   e. Verify: principals, roles, policies, trust relationships all present in graph
   f. Verify: effective permissions computed correctly
   g. Verify: escalation edges derived (optional in this phase, required in Phases 3-7)
   h. Teardown: destroy all Floci resources, clear graph

**Success criteria:**
- [ ] Graph populated with expected nodes for all 5 scenarios
- [ ] Effective permissions computed correctly (no missing edges)
- [ ] Ingestion pipeline runs without errors
- [ ] Query `accountRisks(staging_account_id)` returns data structure with risk fields

### Phase 3: Scenario 1 CF Trap (1d)
**Validate CloudFormation service role escalation detection.**

**Setup:** Seed scenario 1 (dev + staging, CF deploy role, developer role, cross-account trust)

**Queries & Validations:**
```graphql
query {
  principalRisks(principalArn: "arn:aws:iam::111111111111:role/developer-role") {
    signals {
      dangerousActions { count actions }
      crossAccountHops { hopCount }
    }
    escalationPaths { steps { action service } }
    riskScore
  }
}
```
- Expected: `dangerousActions.count ≥ 2` (CF + PassRole + Lambda combo)
- Expected: `crossAccountHops.hopCount ≥ 1`
- Expected: `riskScore > 80`

**Validation points:**
- [ ] `detect_dangerous_actions()` identifies CloudFormation + PassRole + Lambda chain
- [ ] `derive_escalation_edges()` creates edge from developer-role to staging via CF + Lambda
- [ ] `evaluate_passrole_scope()` detects that CF role's wildcard PassRole bypasses scoped restriction
- [ ] `BlastRadiusSignal` includes staging admin role as reachable
- [ ] GraphQL risk score exceeds 80/100

**Failure rollback:** If detection fails, document exactly which function missed the signal

### Phase 4: Scenario 2 OIDC Drift (1d)
**Validate federation policy version drift detection.**

**Setup:** Seed scenario 2 (GitHub OIDC, v1 safe policy → v2 drifted policy, CodePipeline roles, staging + prod)

**Queries & Validations:**
```graphql
query {
  federationRisks(accountId: "222222222222") {
    oidcProviders {
      provider
      trustPolicyVersions {
        version createdAt condition
      }
      drift { direction severity }
    }
    riskScore
  }
}
```
- Expected: `drift.direction = "loosening"`
- Expected: `drift.severity = "High"`
- Expected: `riskScore > 80`

**Validation points:**
- [ ] `analyze_federation_version_drift()` detects policy loosening from v1 to v2
- [ ] `evaluate_condition()` correctly evaluates drifted sub condition with attacker JWT
- [ ] `detect_dangerous_actions()` identifies AssumeRole chain (GitHub → CodePipeline → Prod)
- [ ] Cross-account hop from staging to prod detected
- [ ] Risk score increases when drift detected

**Failure rollback:** If version drift not detected, verify CloudTrail/audit logs have policy change history

### Phase 5: Scenario 3 S3 OrgID (1d)
**Validate resource policy boundary confusion detection.**

**Setup:** Seed scenario 3 (dev bucket with `s3:PutBucketPolicy`, shared data bucket with org-ID condition)

**Queries & Validations:**
```graphql
query {
  resourcePolicyRisks(bucketName: "org-shared-data") {
    policy {
      principal
      condition { type value }
      isTrustBoundary
    }
    crossAccountAccess { accounts severity }
    riskScore
  }
}
```
- Expected: `isTrustBoundary = false` (for org-ID condition)
- Expected: `crossAccountAccess.accounts` includes dev account
- Expected: `riskScore > 75`

**Validation points:**
- [ ] `evaluate_resource_policy_boundary()` identifies org-ID as permissive, not restrictive
- [ ] `detect_cross_account_policy_escalation()` flags shared data bucket as reachable from dev
- [ ] `evaluate_resource_policy_pair()` correctly allows dev account access to org-shared-data bucket
- [ ] Policy decision shows why Principal:* is dangerous even with org-ID condition

**Failure rollback:** If boundary not identified, verify resource policy evaluation logic in IAM module

### Phase 6: Scenario 4 KMS Grant (1d)
**Validate KMS CreateGrant escalation detection.**

**Setup:** Seed scenario 4 (KMS key with grant permissions, application role, infrastructure role in dev account, secrets account)

**Queries & Validations:**
```graphql
query {
  keyManagementRisks(keyId: "12345678-1234-1234-1234-123456789012") {
    keyPolicy {
      statements { action principal }
    }
    createGrantRisk { grantable accounts severity }
    riskScore
  }
}
```
- Expected: `createGrantRisk.severity = "High"`
- Expected: `createGrantRisk.grantable` includes dev account root
- Expected: `riskScore > 70`

**Validation points:**
- [ ] `evaluate_resource_policy_pair()` detects dev account root can CreateGrant on KMS key
- [ ] `detect_grant_escalation()` identifies low-privilege role escalation via account-root grants
- [ ] `detect_dangerous_actions()` flags CreateGrant as dangerous
- [ ] Escalation path from application-role to infrastructure-role to admin visible

**Failure rollback:** If grant escalation not detected, verify CreateGrant is modeled as privilege escalation vector

### Phase 7: Scenario 5 Full Chain (1d)
**Validate multi-vector aggregation and critical risk scoring.**

**Setup:** Seed scenario 5 (all 4 scenarios combined in one environment with 4 accounts)

**Queries & Validations:**
```graphql
query {
  accountRisks(accountId: "222222222222") {
    allSignals {
      cfEscalation { severity }
      oidcDrift { severity }
      s3Boundary { severity }
      kmsGrant { severity }
    }
    cascadeRiskScore
  }
}
```
- Expected: All 4 signals present with severity ≥ High
- Expected: `cascadeRiskScore ≥ 90`
- Expected: Full pipeline (ingest → score → query) completes in < 5 minutes

**Validation points:**
- [ ] All 5 scenario detection functions fire simultaneously
- [ ] Iterative scoring converges across all principals
- [ ] Composite score reflects multi-vector risk
- [ ] Performance: pipeline completes in <5 min
- [ ] No false positives on innocent use cases (legitimate CF, normal OIDC, etc.)

**Failure rollback:** If any signal missing, trace which detection function failed and roll back to that phase

### Phase 8: Results Report + Teardown (0.5d)
**Generate validation matrix, calculate coverage, destroy environments, commit results.**

**Deliverables:**
1. **Validation results matrix** — scenario × detection point, pass/fail
   ```
   | Scenario | Function | Expected | Actual | Pass |
   |----------|----------|----------|--------|------|
   | 1 | detect_dangerous_actions | CF+PassRole+Lambda | DETECTED | ✅ |
   | 2 | analyze_federation_version_drift | Policy loosening | DETECTED | ✅ |
   | ... | ... | ... | ... | ... |
   ```

2. **Coverage calculation** — `detected / total detection points × 100`
   - Target: ≥95% coverage

3. **Teardown sequence:**
   - Floci: `docker-compose down -v` (removes volumes)
   - Real AWS: `aws-nuke -c config-whitelist.yaml --force` (targets test accounts only)
   - Graph: `psql -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"` (reset DB)

4. **Report markdown:** `plans/reports/adversarial-validation-results-20260524.md`
   - Summary: coverage %, pass/fail per scenario
   - Narrative: which detection functions worked, which need fixes
   - Carry-forward: any missed detection points → items for SkyEye Phase 02

**Success criteria:**
- [ ] Coverage ≥95% (all 5 scenarios + 5 detection functions validated)
- [ ] All resources destroyed (no orphaned AWS resources, docker images cleaned)
- [ ] Report committed to `plans/reports/`

---

## Success Criteria (Overall)

- [ ] All 8 phases complete without errors
- [ ] Coverage ≥95% (≥24/25 detection points pass)
- [ ] No detection false positives on innocent cases
- [ ] Full pipeline (ingest → score → query) completes in <5 min for all scenarios
- [ ] Report documents which detection functions succeeded and which need future work
- [ ] Real AWS validation confirms Floci results transfer to production-like environment
- [ ] All environments torn down (zero AWS resource leaks)

---

## Unresolved Questions

1. **Real AWS account access:** Does user have 3+ sandboxed accounts provisioned? Or should Phase 1 include account creation workflow?
2. **GraphQL API finalization:** Are the query shapes (`principalRisks`, `federationRisks`, `resourcePolicyRisks`, `keyManagementRisks`, `accountRisks`) finalized in `activable-graphql` implementation?
3. **Multi-account IAM deployment:** Should Phase 1 include CloudFormation StackSet template creation, or assume manual account setup?
4. **aws-nuke config:** Does user have AWS account whitelist config for `aws-nuke`, or should Phase 1 scaffold it?

---

## Dependencies

- Phase 1 blocks Phase 2
- Phase 2 blocks Phases 3-7 (can run in parallel)
- Phases 3-7 block Phase 8

---

## Reference Documents

- Scenario definitions: `plans/260524-1400-skyeye-full-coverage/adversarial-validation-scenarios.md`
- Parent plan: `plans/260524-1400-skyeye-full-coverage/plan.md`
- CLAUDE.md Section 0: Development rules + hard constraints
