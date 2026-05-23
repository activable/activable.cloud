---
title: "SkyEye full coverage — 40% to 100%"
description: "Comprehensive roadmap to close all major gaps identified in SkyEye paper (arXiv:2507.21094v2). Target: resource policies, federation, ABAC, temporal tracking, fuzzing, CloudTrail integration bringing platform from 40% to 100% coverage."
status: pending
priority: P1
effort: 24-34w
branch: "feat/rust-ingestion"
tags: [rust, iam, security, risk-scoring, resource-policies, federation, abac, temporal, fuzzing, skyeye, aws]
blockedBy: ["260523-v2-iam-risk-scoring"]
blocks: []
created: "2026-05-23"
createdBy: "tech-lead"
source: user
---

# SkyEye Full Coverage — 40% → 100%

## Executive Summary

**Goal:** Close all major SkyEye coverage gaps (arXiv:2507.21094v2), from 40% → 95%+ coverage.

**Status as of 2026-05-24:**
- Phases 1-10: code implemented (detection functions, parsers, evaluators, signals)
- Phase 11: integration tests written
- **E2E validation: PARTIAL** — Floci ingestion creates graph nodes with trust policies, but enricher pipeline doesn't create permission edges from native SDK fallback path. Risk scoring blocked until edges exist.

**Remaining work (E2E blockers — not new features):**
1. Fix enricher to run after native SDK fallback (not just CCAPI) — creates HasEffectivePermission + CanEscalateTo edges
2. Store inline policies as JSON string (AGE doesn't support JSON arrays as properties)
3. Fix GraphClientAdapter.list_principal_ids() Cypher to handle AGE node format
4. Re-run E2E: seed Floci → ingest → enricher creates edges → risk scoring → real detection report

**Effort remaining:** ~3-5d engineering to fix ingestion pipeline gaps, then E2E re-run.

**Adversarial validation plan:** 5 red-team scenarios designed (CF trap, OIDC drift, S3 OrgID confusion, KMS CreateGrant, full kill chain). See `adversarial-validation-scenarios.md`. Execution plan at `../260524-adversarial-scenario-execution/`.

**E2E report (honest):** `../reports/adversarial-e2e-validation-260524.md` — documents what works and what's blocked.

---

## Phase Dependency Graph

```
Phase 01: GraphClientAdapter (foundation)
    ↓
Phase 02: Resource policies (S3/SNS/SQS/KMS/Lambda)
    ↓
Phase 03: Multi-credential enumeration loop
    ↓
Phase 04: Session policy constraints
    ↓
Phase 05: ABAC tag manipulation detection
    ↓
Phase 06: Federated identity analysis
    ↓
Phase 07: Temporal policy version tracking
    ↓
Phase 08: CloudTrail audit trail integration
    ↓
Phase 09: IAM action fuzzing engine
    ↓
Phase 10: AWS service permission expansion tracking
    ↓
Phase 11: Integration testing + calibration
```

---

## Conditional Gates

| Gate | Condition | Blocks | If fails |
|------|-----------|--------|----------|
| **Parliament baseline** | Agreement ≥80% on S3-only corpus (after Phase 02 resource policy parser tested on 20+ policies) | Phase 03+ | Halt Phase 02. Investigate: parser error? evaluator bug? Debug test policies; fix parser logic before proceeding. |
| **Convergence** | Phase 03 multi-credential enumeration converges in <5 iterations on 100-principal test scenario (verify via iteration logs) | Phase 04+ | Halt Phase 03. Investigate: cycle detection? Evaluator oscillating? Add logging; analyze edge-growth per iteration; fix cycle detection before proceeding. |
| **Fuzzing enablement** | Phase 09 fuzzer generates ≥5 novel escalation combos on 10-principal test corpus (not false positives); first 10 discovered patterns reviewed + approved by tech lead | Phase 09 enabled | Keep fuzzing disabled (config/fuzzing_config.yaml::enabled: false). Defer enabling to Phase 11 manual review or Phase 09.5. |
| **Signal calibration baseline** | Phase 01 baseline signal weights measured on synthetic 50-principal scenario; blast_radius, path_to_admin, policy_complexity stable across repeated runs | Phase 02+ scoring | Halt Phase 01. Investigate: signal computation unstable? Test input insufficient? Expand synthetic scenario or fix signal logic before Phase 02. |
| **CloudTrail parse rate** | Phase 08 CloudTrail event parser achieves ≥99% success rate on 1000+ real CloudTrail events; <1% malformed/skipped | Phase 08+ enrichment | Halt Phase 08. Investigate: which events fail parsing? Malformed JSON? AWS API variations? Debug failures; expand parser; re-test on 1K sample. |

---

## Phase Status

| Phase | Gap Addressed | Code | Tests | E2E | Status |
|-------|---|---|---|---|---|
| 01 | GraphClientAdapter | ✅ | ✅ | ✅ nodes written via Cypher | **DONE** |
| 02 | Resource-based policies | ✅ 40 tests | ✅ parser + evaluator | ❌ not wired to ingestion pipeline | **CODE DONE, E2E BLOCKED** |
| 03 | Multi-credential enumeration | ✅ 24 tests | ✅ convergence + cycle | ❌ needs permission edges | **CODE DONE, E2E BLOCKED** |
| 04 | Session policy constraints | ✅ 20 tests | ✅ intersection logic | ❌ needs permission edges | **CODE DONE, E2E BLOCKED** |
| 05 | ABAC tag manipulation | ✅ 29 tests | ✅ self-tag detection | ❌ needs permission edges | **CODE DONE, E2E BLOCKED** |
| 06 | Federated identity | ✅ 27 tests | ✅ weak OIDC detection | ❌ needs trust policy parsing in enricher | **CODE DONE, E2E BLOCKED** |
| 07 | Temporal policy drift | ✅ 27 tests | ✅ semantic diff | ❌ needs version history | **CODE DONE, E2E BLOCKED** |
| 08 | CloudTrail integration | ✅ 26 tests | ✅ pattern detection | ❌ needs event ingestion | **CODE DONE, E2E BLOCKED** |
| 09 | IAM action fuzzing | ✅ 22 tests | ✅ combo enumeration | ❌ needs permission data | **CODE DONE, E2E BLOCKED** |
| 10 | Service catalog tracking | ✅ 12 tests | ✅ diff + impact | N/A (offline analysis) | **CODE DONE** |
| 11 | Integration tests | ✅ 21 tests | ✅ | ❌ needs edges for real scores | **CODE DONE, E2E BLOCKED** |

### E2E Blocker: Ingestion Pipeline Gap

All phases have working code + tests (763 pass). The blocker is the **ingestion pipeline**:

```
Floci (IAM roles + policies exist)
  ↓ CCAPI: returns empty (Floci doesn't support CloudControl)
  ↓ Native SDK fallback: creates Principal nodes WITH trust policies ✅
  ↓ BUT: enricher doesn't run on fallback-ingested nodes ❌
  ↓ Result: 9 nodes, 0 edges
  ↓ Risk scoring: "no permissions found"
```

**Fix needed (3-5d):**
1. Enricher pipeline must run after native SDK fallback (currently only runs after CCAPI)
2. Inline policies must be stored as JSON string (AGE doesn't support arrays)
3. Enricher must parse stored policies → create HasEffectivePermission + CanEscalateTo edges
4. GraphClientAdapter queries must handle AGE's agtype format for list_principal_ids()

After fix → re-run E2E → real risk scores from real engine against real Floci data.

---

## Phase Files

- **Phase 01:** [GraphClientAdapter foundation](./phase-01-graphclient-adapter-foundation.md)
- **Phase 02:** [Resource-based policy ingestion + evaluation](./phase-02-resource-policies-s3-sns-sqs.md)
- **Phase 03:** [Multi-credential enumeration loop](./phase-03-multi-credential-enumeration.md)
- **Phase 04:** [Session policy constraints](./phase-04-session-policy-constraints.md)
- **Phase 05:** [ABAC tag manipulation detection](./phase-05-abac-tag-manipulation.md)
- **Phase 06:** [Federated identity analysis](./phase-06-federated-identity-analysis.md)
- **Phase 07:** [Temporal policy version tracking](./phase-07-temporal-policy-versions.md)
- **Phase 08:** [CloudTrail audit trail integration](./phase-08-cloudtrail-integration.md)
- **Phase 09:** [IAM action fuzzing engine](./phase-09-fuzzing-engine.md)
- **Phase 10:** [AWS service permission expansion tracking](./phase-10-service-permission-tracking.md)
- **Phase 11:** [Integration testing + calibration](./phase-11-integration-testing.md)

---

## Team Composition & Roles

| Role | Model | Responsibilities |
|------|-------|---|
| Orchestrator (Tech Lead) | Haiku | Plan review, phase approval, sub-agent dispatch, final integration |
| Implementation Engineers | Sonnet | Code implementation per phase plans, TDD-mode testing |
| Test Engineers | Sonnet | Test suite design, coverage validation, regression testing |
| Code Reviewers | Sonnet | Pre-merge quality gates, architecture verification |
| Researcher (optional) | Sonnet | AWS API research, threat model validation, SkyEye paper alignment |

---

## Success Criteria (End-to-End)

✅ **Coverage:** 95% of Tier 1/2 SkyEye gaps (85%+ of full inventory); 12 remaining gaps deferred for future work
✅ **Parliament agreement:** ≥90% agreement on expanded IAM corpus (resource + identity policies)
✅ **CloudGoat regression:** All SkyEye-relevant CloudGoat scenarios detected
✅ **Performance:** Graph queries for resource-policy chains return <100ms
✅ **Accuracy:** No >20% false positive rate on new signals
✅ **Testing:** ≥98% branch coverage across all new modules per phase
✅ **Documentation:** GraphQL schema updated with resource-policy, federation, temporal types

---

---

## File Ownership + Merge Strategy

| File/Directory | Owner Phase | Other phases may |
|---|---|---|
| `config/escalation-paths/bundled/` | Phase 11 (final taxonomy) | Add new files (e.g., `phase-XX-escalation-rules.yaml`), never modify existing |
| `activable-schema/src/labels.rs` | Phase 01 (adds all new NodeLabel/EdgeType variants upfront) | Read only; all variant names pre-declared in Phase 01 |
| `activable-risk/src/scorer.rs` | Phase 01 (signal framework + aggregation formula) | Read only; phases add signal implementations via trait registration, not code edits |
| `activable-risk/src/signals/mod.rs` | Phase 01 (trait definition) | Add signal implementations in separate files (e.g., `policy_drift_signal.rs`); register via trait, not code change |
| `activable-ingest/src/lib.rs` | Phase 01 (core pipeline orchestration) | Read; phases add enricher modules, call them from main pipeline in dedicated `match phase_number` or feature gate |
| `activable-graphql/src/resolvers/mod.rs` | Phase 01 (resolver framework) | Add resolver functions in separate files (e.g., `resource_policy_resolver.rs`); export, don't edit core module |
| Per-phase module directories | Owner phase (e.g., Phase 02 owns `activable-ingest/src/resource_policy/`) | Read only; encapsulated within phase directory |

### Merge Strategy

**Sequential merging (not parallel):** Each phase merged to main sequentially after passing tests.

| Merge sequence | Phase | Branch | Action |
|---|---|---|---|
| 1 | Phase 01 | `feat/skyeye-phase-01` | Create full feature branch; pass all tests; merge via PR (squash) |
| 2 | Phase 02 | `feat/skyeye-phase-02` | Branch from main (Phase 01 merged); pass Phase 01 gates + Phase 02 tests; merge |
| 3-11 | Phases 03-11 | `feat/skyeye-phase-XX` | Follow same pattern; each phase depends on prior phases merged |

**Config files (escalation rules, dangerous actions, YAML):**
- **Append-only:** Phases add new YAML files (e.g., `phase-02-resource-policy-combos.yaml`), never edit existing files
- **Central registry:** Phase 11 integrates all bundled rules into final unified taxonomy (optional, for documentation)
- **Schema immutability:** Phase 01 pre-declares ALL NodeLabel/EdgeType variants; subsequent phases reference but don't modify

---

## Key Design Principles

### 1. **Extensibility via YAML Config**

Do NOT add logic to code for registries. Instead, extend YAML:
- `dangerous-actions.yaml` — new dangerous actions (tag-manipulation, federation-bypass, etc.)
- `escalation-paths/bundled/` — new escalation rules (resource-policy combos, ABAC bypass, etc.)
- `resource_types.yaml` — new AWS service resource types (CloudWatch Rules, Step Functions, etc.)
- `relationships.yaml` — new relationship types (ResourcePolicyAllows, FederatedTrust, etc.)

### 2. **Trait-Based Graph Querying**

Phase 01 replaces `InMemoryGraphService` (test-only) with real `GraphClient` adapter implementing `GraphQueryService`. All subsequent phases use trait only — no re-architecture needed.

### 3. **Layered Policy Evaluation**

Build on existing condition evaluator:
- **Phase 04:** Session policy = resource-derived condition constraint (reuse condition evaluator)
- **Phase 05:** ABAC tags = new condition type (extend condition evaluator)
- **Phase 06:** Federation conditions = external IdP-derived conditions (extend condition evaluator)

### 4. **Temporal Signals via Graph Versioning**

Do NOT snapshot full policy versions in graph. Instead:
- Store `PolicyVersion` node type (lightweight: policy_arn, version_id, created_at)
- Store version history in separate index (RocksDB or S3)
- Diff-on-demand: compare versions when risk scoring, flag expansion as signal

### 5. **Fuzzing via Deterministic Permutations**

Do NOT random fuzzing. Fuzzing = deterministic enumeration + pruning:
- Enumerate 2-3 action combos per service family
- Test against `effective_permissions()` + `match_all_rules()`
- Prune combos already covered by escalation rules
- Log novel combos → auto-generate new rules

---

## Risk Assessment

### Tier 1: Critical Risks (Likelihood: Medium, Impact: High)

| Risk | Mitigation |
|------|---|
| **Graph query performance degrades with resource policies** | Phase 01: benchmark Cypher query patterns before code freeze. Add indexing on PolicyArn, ServiceType. |
| **Session/federation/ABAC conditions explode rule-match complexity** | Phase 04+: reuse existing condition evaluator (O(n) per condition type), don't rewrite. Test with 1000+ conditions per policy. |
| **CloudTrail batch ingestion blocks main ingest pipeline** | Phase 08: async job queue; CloudTrail ingestion runs separately, enriches graph asynchronously post-ingest. |
| **Fuzzing discovers too many false-positive escalation patterns** | Phase 09: pruning strategy critical. Test fuzzer against Parliament corpus; discard combos with <5% real-world prevalence. |

### Tier 2: Medium Risks (Likelihood: High, Impact: Medium)

| Risk | Mitigation |
|------|---|
| **AWS service APIs rate-limiting during multi-credential enumeration** | Phase 03: batch principal enumeration (max 10 principals per sweep), exponential backoff. Cache results. |
| **Resource policy formats differ per service; new parsers fragile** | Phase 02: start with S3 (most common), validate parser against 100+ real buckets before SNS/SQS. Use official boto3 policy parser as reference. |
| **Parliament doesn't have resource-policy coverage; agreement baseline unclear** | Phase 02: establish agreement baseline on S3-only corpus first (easier to validate), then expand. |

### Tier 3: Lower Risks (Likelihood: Low, Impact: Low)

| Risk | Mitigation |
|------|---|
| **New node/edge types break existing GraphQL queries** | Phase 01: verify backward compatibility of all GraphQL endpoints after schema extension. |
| **YAML config explosion (too many rules, hard to maintain)** | Phase 05+: document rule taxonomy in CLAUDE.md. Auto-generate rule index from YAML. Set max rule count alerts. |

---

## Testing Strategy per Phase

### Unit Tests (Crate-Level)

- **activable-schema:** NodeLabel/EdgeType variants; ARN canonicalization for new resource types
- **activable-ingest:** Resource type parsers (S3, SNS, SQS); relationship extraction
- **activable-ingest-iam:** Resource policy parser; cross-account/same-account evaluation; session policy intersection
- **activable-risk:** Multi-credential orchestration; signal computation for new signals; fuzzing engine output validation
- **activable-graphql:** GraphQL resolvers for new types (ResourcePolicy, FederatedProvider, PolicyVersion, AuditEvent)

### Integration Tests

- **Real AWS environment (or moto mock):**
  - S3 bucket policy ingestion + evaluation (cross-account scenarios)
  - IAM role with session policy + resource policy (three-layer evaluation)
  - SAML/OIDC trust policy parsing + federation condition evaluation
  - CloudTrail event batch ingestion → graph enrichment
  - Multi-principal escalation chain discovery (10+ principals)

- **Parliament agreement:**
  - Corpus: expanded dataset with resource policies, federation, ABAC
  - Gate: ≥90% agreement before Phase 11 merge
  - Metric: false positives + false negatives per escalation class

### Regression Testing

- **CloudGoat scenarios:**
  - RDS privilege escalation (resource policy + identity policy)
  - EC2 cross-account escalation via resource policy
  - Lambda federation abuse (SAML/OIDC + resource policy)
  - S3 bucket policy cross-account access
  - KMS key policy + IAM escalation (grantTokens)

- **Coverage targets:**
  - SkyEye problem inventory: 95%+ scored as addressed
  - Blast radius signal: ≥90% agreement with manual graph traversal
  - Fuzzing discovery: <5% novel combos, >95% plausible

---

---

## AWS API Failure Handling

| Failure mode | Handling | Phases affected | Implementation detail |
|---|---|---|---|
| **API throttling (429)** | Exponential backoff (1s, 2s, 4s, 8s, max 60s). Max 5 retries. | 02, 03, 06, 07 | Implement in AWS SDK client config or wrapper; return error if all retries exhausted. Log each retry. |
| **API unavailable (5xx)** | Skip resource type, log warning, continue with remaining. Mark ingest as partial. | 02, 06 | Graceful degradation; don't fail entire batch. Document which resource types unavailable. |
| **Partial ingestion** | Track per-resource-type success rate. Alert if <90% of types succeed. | 02, 03, 06 | Return PartialResult with success_rate field; log failures by resource type. |
| **Data staleness** | Resource policies must be ≤24h old at scoring time. Stale data flagged in assessment. | 02, 07 | Store fetch_timestamp on resource policy node; check at scoring time; flag in risk assessment if stale. |
| **Missing permissions** | IAM policy must include read access for all resource policy APIs. Document minimum IAM policy. | 02, 06, 07, 08 | Validate at startup; return clear error with minimum required permissions; document in DEPLOYMENT.md. |
| **CloudTrail gaps** | If <7 days of logs available, proceed with available data. Flag coverage gap in assessment. | 08 | Check CloudTrail status; log available date range; include gap note in AuditEvent metadata. |
| **Deleted policies** | If ListPolicyVersions returns 0 versions, skip. Log warning. | 07 | Handle None/empty response; don't error; log warning with policy ARN. |
| **Rate-limited enumeration** | Batch principal enumeration (max 10 principals per sweep). Implement exponential backoff. Cache results. | 03 | Use ListUsers pagination; batch requests; cache IAM state for duration of batch run. |

---

## Backward Compatibility & Migration

### Schema Changes

- **NodeLabel:** Adding new variants (ResourcePolicy, FederatedProvider, PolicyVersion, AuditEvent) is backward compatible (Custom(String) already exists as fallback).
- **EdgeType:** Adding new variants (ResourcePolicyAllows, ResourcePolicyDenies, FederatedTrust, VersionedFrom) is backward compatible.
- **GraphQL:** New types (`ResourcePolicy`, `FederationProvider`, `PolicyVersion`, `AuditEvent`) added to schema; existing types remain unchanged.

### Data Migration

- **Phase 02 onward:** New policies ingested alongside existing identity policies. No re-ingestion of old data required.
- **Phase 07:** Historical policy versions fetched on-demand; no backfill required (lazy loading).
- **Phase 08:** CloudTrail events ingested separately; no blocking of existing ingest pipeline.

### API Stability

- All existing GraphQL queries remain valid. New queries added for resource-policy evaluation, federation, temporal analysis.
- Risk scoring API extended with new signal types; existing signals unchanged.

---

## Success Validation Checklist

### After Phase 01 (Foundation)
- [ ] GraphClientAdapter passes all 7 GraphQueryService trait tests
- [ ] Cypher queries benchmark <100ms for 10K-node graphs
- [ ] All existing tests pass (no regression)

### After Phase 02 (Resource Policies)
- [ ] S3 bucket policy parser tested against 100+ real policies
- [ ] Cross-account vs same-account evaluation validated
- [ ] Parliament agreement baseline established
- [ ] New escalation rules for resource-policy combos documented

### After Phase 03 (Multi-Credential)
- [ ] Principal enumeration covers 500+ principals efficiently
- [ ] Multi-principal chains detected correctly
- [ ] Performance remains <5s for batch scoring

### After Phases 04-07 (Layers: Session, ABAC, Federation, Temporal)
- [ ] Session policy constraints reduce false positives by ≥10%
- [ ] ABAC tag manipulation vectors detected in test scenarios
- [ ] Federation trust chains modeled correctly
- [ ] Policy version drift identified in mock scenarios

### After Phases 08-10 (CloudTrail, Fuzzing, Service Tracking)
- [ ] CloudTrail batch ingestion adds <10% overhead
- [ ] Fuzzing discovers ≥5 novel escalation patterns
- [ ] Service permission expansion detected in AWS IAM reference

### After Phase 11 (Integration)
- [ ] SkyEye inventory scoring: 95%+ addressed
- [ ] Parliament agreement: ≥90%
- [ ] CloudGoat regression: 100% SkyEye scenarios detected
- [ ] Performance: graph queries <100ms, batch scoring <10s for 10K principals
- [ ] Coverage: ≥98% branch coverage across new code
- [ ] Docs: GraphQL schema, YAML rule taxonomy, threat model updated

---

## Effort Breakdown

| Phase | Role | Effort | Notes |
|---|---|---|---|
| 01 | Engineer + Tester | 5d | GraphClientAdapter, Cypher query design, benchmarking, transaction semantics, baseline signal calibration |
| 02 | Engineer + Researcher + Tester | 9d | Per-service resource policy adapters, Parliament baseline establishment, escalation rules |
| 03 | Engineer + Tester | 7d | Enumeration loop, cycle detection, O(n²) mitigation, principal discovery, re-scoring orchestration |
| 04 | Engineer + Tester | 2d | Session policy intersection (reuses condition evaluator) |
| 05 | Engineer + Researcher + Tester | 5d | NotPrincipalTag/NotResourceTag inversion, tag parser, ABAC conditions, attacker model |
| 06 | Engineer + Researcher + Tester | 9d | SAML/OIDC parsers, federation trust graph, condition evaluation |
| 07 | Engineer + Tester | 4d | Semantic action-level diff, version history API, NotAction expansion detection, signal integration |
| 08 | Engineer + Tester | 6d | Malformed event quarantine, CloudTrail parser, async job queue, event enrichment, alert gates |
| 09 | Engineer + Tester | 8d | Fuzzing enablement gate, permutation logic, rule generation (90% coverage, post-1M principals) |
| 10 | Researcher + Engineer | 2d | AWS IAM action tracking, versioning schema |
| 11 | Engineer + Tester + Code-Reviewer | 12d | 12 remaining gaps documentation, Parliament agreement validation, CloudGoat regression, performance tuning, final docs |
| **TOTAL** | — | **68d** | ~14 weeks (Sonnet) or ~18 weeks (mixed Haiku/Sonnet) |

**Adjustment:** If phases run sequentially with one eng + one tester: ~12 weeks. If two teams parallel: ~6 weeks. Use Sonnet for phases 2, 5, 6, 8, 9 (complex logic); Haiku for phases 1, 3, 4, 7, 10, 11.

---

## Key References

- **SkyEye paper:** arXiv:2507.21094v2 (sections 3-5: policy evaluation, 4: escalation chains, 6-7: temporal analysis, 12: fuzzing)
- **Coverage analysis:** `plans/reports/coverage-analysis-paper-2507.21094v2.md`
- **Prior plan (completed):** `plans/260523-v2-iam-risk-scoring/` (9 phases shipped)
- **Existing crates:** activable-schema, activable-ingest, activable-ingest-iam, activable-risk, activable-graphql
- **AWS APIs:**
  - Resource policies: GetBucketPolicy, GetPolicy, GetKeyPolicy, GetTopicAttributes, GetQueueAttributes, GetRepositoryPolicy
  - Federation: ListSAMLProviders, ListOpenIDConnectProviders, GetSAMLProvider, GetOpenIDConnectProvider
  - Versions: ListPolicyVersions, GetPolicyVersion
  - CloudTrail: ListTrails, GetTrailStatus, LookupEvents (or CloudTrail Lake)

---

## Next Steps

1. **Tech lead:** Review all 11 phase files for dependencies, effort accuracy, risk mitigation
2. **Lead:** Approve plan → set Sonnet floor for implementation agents
3. **Engineers:** Start Phase 01 (GraphClientAdapter foundation) immediately; unblocks all others
4. **Researcher:** Run AWS API survey (Phase 02-06) in parallel with Phase 01
5. **Tester:** Draft test suites for Phases 01-03 in parallel with implementation
6. **Lead:** Sync with project stakeholders on 4-6 month timeline + coverage targets

---

## Appendix: SkyEye Paper Problem Inventory

See `plans/reports/coverage-analysis-paper-2507.21094v2.md` for full breakdown. Key gaps:

**Tier 1 (high impact, medium effort):**
1. Multi-credential enumeration (Phase 03)
2. Resource-based policies (Phase 02)
3. Temporal policy drift (Phase 07)
4. Fuzzing for unknown patterns (Phase 09)

**Tier 2 (medium impact, low-medium effort):**
5. Session policy constraints (Phase 04)
6. ABAC tag manipulation (Phase 05)
7. Federated identity support (Phase 06)

**Tier 3 (lower impact, higher effort or out-of-scope):**
8. CloudTrail audit trail (Phase 08) — optional runtime enrichment
9. AWS service permission versioning (Phase 10) — optional capability tracking

---

**Plan ready for review and approval.**
