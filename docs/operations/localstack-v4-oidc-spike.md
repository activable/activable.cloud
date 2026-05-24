# LocalStack v4.7 CE — OIDC + Multi-account spike

**Date:** 2026-05-24
**Spike runner:** Phase 1 Day-1 blocking decision per `plans/260524-detection-engine-client-readiness/phase-01-detection-engine-quick-fixes.md` Step 0.
**Verdict:** ✅ **PASS** on both capabilities.

## Spike methodology

```bash
docker pull localstack/localstack:4.7
docker run -d --name localstack-oidc-spike -p 14566:4566 \
  -e SERVICES=iam,sts \
  -e ALLOW_NONSTANDARD_REGIONS=1 \
  localstack/localstack:4.7
# wait for /_localstack/health to return iam=available
```

## Test 1 — OIDC provider creation

```bash
AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  aws --endpoint-url http://localhost:14566 --region us-east-1 \
  iam create-open-id-connect-provider \
    --url https://token.actions.githubusercontent.com \
    --client-id-list sts.amazonaws.com \
    --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

**Result:**
```json
{
  "OpenIDConnectProviderArn": "arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"
}
```

`list-open-id-connect-providers` returns the created provider. **No `UnsupportedOperation` error.** Contrast: community Floci fork returned `UnsupportedOperation` on the same call (validation report §"Floci limitations").

## Test 2 — Multi-account routing

```bash
AWS_ACCESS_KEY_ID=111111111111 AWS_SECRET_ACCESS_KEY=test \
  aws --endpoint-url http://localhost:14566 --region us-east-1 \
  iam create-role --role-name dev-role-test --assume-role-policy-document '{...}'
# → Role ARN: arn:aws:iam::111111111111:role/dev-role-test  ✓

AWS_ACCESS_KEY_ID=222222222222 AWS_SECRET_ACCESS_KEY=test \
  aws --endpoint-url http://localhost:14566 --region us-east-1 \
  sts get-caller-identity
# → Account: 222222222222  ✓
```

**Result:** account ID encoded in `AWS_ACCESS_KEY_ID` routes the entity to that account. Multi-account model from the adversarial-scenarios doc is reproducible.

## Implications for the plan

| Plan element | OIDC PASS impact |
|---|---|
| Phase 4 `federationRisks` resolver | Build the FULL implementation (per `phase-04` architecture). The OIDC-fail stub fallback is NOT needed. |
| Phase 5 seed script | Un-guard the `if false` block around Scenario 2 OIDC. Multi-account routing works — remove "collapse to 000000000000" workarounds. |
| Scenario 2 acceptance | `riskScore > 0.80` is the binding gate (no carry-forward). |
| Floci → LocalStack swap | Pure win: more capabilities, free, no Pro license needed. |

## Caveats / unknowns

- OIDC provider ARN still shows `arn:aws:iam::000000000000:...` despite multi-account being supported elsewhere. This may be a known LocalStack quirk for OIDC providers specifically. **Not a blocker** for Scenario 2 detection since the trust-policy version-drift logic doesn't rely on the provider's account ID.
- Spike used only `iam` + `sts` services. KMS + S3 + Organizations services need a re-test before Phase 3 / Phase 5 deployment. Add to Phase 3 + Phase 5 entry tasks.
- Did not test `update-open-id-connect-provider-thumbprint` (used by the trust-policy-drift scenario). Phase 5 seed script should validate this works.

## Decision

**Proceed with `phase-04` OIDC PASS path:** ship full `federationRisks` resolver. Drop the stub fallback option from Phase 4 scope. Phase 5 seed script enables Scenario 2.
