# On-Call Runbook: Detection Engine Failures

When the detection engine reports false negatives or false positives for the 5 adversarial scenarios, use this runbook to diagnose the root cause.

## Overview

The detection engine has 5 distinct adversarial scenarios, each exercising a specific privilege escalation path. This runbook covers:

1. **Scenario 1: CloudFormation Service Role Trap** — PassRole + CloudFormation escalation
2. **Scenario 2: GitHub Actions OIDC Configuration Drift** — Federated identity misconfigurations
3. **Scenario 3: S3 Bucket Policy Principal Boundary Confusion** — Cross-account bucket access
4. **Scenario 4: KMS CreateGrant Lateral Movement** — Grant-based key escalation
5. (Scenario 5 reserved for future enhancement)

For each scenario, this runbook lists:
- What the scenario detects (plain English)
- The GraphQL query to verify detection
- Expected risk-score range under healthy conditions
- Top causes of false negatives (scenario not detected when it should be)
- Top causes of false positives (scenario detected when it shouldn't be)
- Where to look first for debugging

## Scenario 1: CloudFormation Service Role Trap

### What It Detects

A principal with both `iam:PassRole` AND `cloudformation:CreateStack` (or similar CloudFormation mutating actions) can escalate privileges by passing a more-privileged role to CloudFormation. CloudFormation will execute the template with the passed role's permissions, allowing the attacker to perform actions they don't have directly.

**Attack example:** Developer role (with S3 read + CloudFormation write) passes the `cf-deploy-production-role` (with IAM create + role creation) to CloudFormation. CloudFormation executes as the production role, allowing the developer to create new roles and escalate indefinitely.

### Verify Detection

Run the GraphQL query to check if the `cf-passrole-001` rule is firing for account 111 (dev):

```bash
curl -s -X POST http://localhost:30080/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ accountRisks(accountId: \"111111111111\") { cascadeRiskScore allSignals { cfEscalation { score severity matchedRuleIds } } } }"
  }' | jq .
```

Expected output:

```json
{
  "data": {
    "accountRisks": {
      "cascadeRiskScore": 0.42,
      "allSignals": {
        "cfEscalation": {
          "score": 0.42,
          "severity": "MEDIUM",
          "matchedRuleIds": [
            "cf-passrole-001",
            "iam-update-trust-001",
            "lambda-001"
          ]
        }
      }
    }
  }
}
```

**Healthy condition:** `score >= 0.40`, rule `cf-passrole-001` in `matchedRuleIds`.

If the score is 0 or the rule is missing, see troubleshooting below.

### Top Causes of False Negatives

**1. IAM policies not ingested**
- Symptom: `cascadeRiskScore` is 0 or null.
- Check: Verify that the ingestion actually read IAM policies from account 111.
  ```bash
  curl -s -X POST http://localhost:30080/graphql \
    -H "Content-Type: application/json" \
    -d '{
      "query": "{ findNode(label: \"Principal\", id: \"arn:aws:iam::111111111111:role/developer-role\") { id label properties } }"
    }' | jq .
  ```
  If the node is null, ingestion didn't create the role. Check ingestion logs.

**2. Ingestion incomplete**
- Symptom: Roles exist but risk score is 0.
- Check: Query the database directly to count nodes per account:
  ```bash
  kubectl exec -it activable-postgres-0 -- psql -U activable -d activable -c \
    "MATCH (n:Principal {account: '111111111111'}) RETURN COUNT(n) as role_count;"
  ```
  If the count is 0, re-trigger ingestion: `make dev-ingest`.

**3. Rule definition not loaded**
- Symptom: Other rules (like `lambda-001`) fire, but `cf-passrole-001` does not.
- Check: Verify the rule file exists and is valid YAML:
  ```bash
  cat crates/activable-risk/config/escalation-paths/bundled/cf-passrole-001.yaml
  ```
  If missing or malformed, rebuild and redeploy:
  ```bash
  make build-linux && make deploy-dev
  ```

**4. Permissions don't match the rule definition**
- Symptom: Rules fire, but the score is lower than expected.
- Check: Confirm that the seeded role has BOTH `iam:PassRole` AND the CloudFormation action:
  ```bash
  kubectl exec -it activable-postgres-0 -- psql -U activable -d activable -c \
    "MATCH (p:Principal {arn: 'arn:aws:iam::111111111111:role/developer-role'})-[:HasPermission]->(perm:Permission) \
     RETURN perm.action as action ORDER BY action;"
  ```
  The output should include `cloudformation:CreateStack` and `iam:PassRole`.

### Top Causes of False Positives

**1. Over-broad permission matching**
- Symptom: Rules fire for accounts that shouldn't be risky.
- Root cause: The rule matching logic might be using wildcards too aggressively (e.g., matching `s3:*` against the rule's specific `s3:GetObject` check).
- Check: Review the matched principals and their actual permissions in the graph:
  ```bash
  curl -s -X POST http://localhost:30080/graphql \
    -H "Content-Type: application/json" \
    -d '{
      "query": "{ findings(minSeverity: \"MEDIUM\") { cascadeRiskScore allSignals { cfEscalation { matchedRuleIds } } } }"
    }' | jq '.data.findings[] | select(.allSignals.cfEscalation.matchedRuleIds[] == "cf-passrole-001")'
  ```
  If non-escalation roles appear, the rule is over-matching.

**2. Trust policy allows unintended cross-account assumption**
- Symptom: Staging or prod accounts show high CloudFormation scores.
- Root cause: A trust policy may inadvertently allow cross-account assumption, which the rule counts as a pathway.
- Check: Query trust policies for unexpected principals:
  ```bash
  kubectl exec -it activable-postgres-0 -- psql -U activable -d activable -c \
    "MATCH (r:Principal {type: 'Role'})-[:HasTrustPolicy]-(tp:TrustPolicy {principal: '*'}) \
     RETURN r.arn, tp.effect, tp.principal LIMIT 10;"
  ```

## Scenario 2: GitHub Actions OIDC Configuration Drift

### What It Detects

A federated identity (OIDC provider) with a drifted trust policy can be assumed by unintended principals or be used to escalate across accounts. The seed script configures a GitHub OIDC provider with conditions on `repo:` and `environment:` but keeps these loose, allowing any GitHub-hosted repository in an organization to assume the staging role.

**Attack example:** An attacker with a GitHub Actions runner can assume the `github-actions-role` in staging, which can assume `codepipeline-deploy-role` in staging, which can assume `codepipeline-prod-deployer` in production. This allows code changes in an unvetted repository to deploy to production.

### Verify Detection

Run the GraphQL query to check if OIDC drift is detected for account 222 (staging):

```bash
curl -s -X POST http://localhost:30080/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ accountRisks(accountId: \"222222222222\") { cascadeRiskScore allSignals { oidcDrift { score severity matchedRuleIds } } } }"
  }' | jq .
```

Expected output (if OIDC drift detection is enabled):

```json
{
  "data": {
    "accountRisks": {
      "cascadeRiskScore": 0.43,
      "allSignals": {
        "oidcDrift": {
          "score": 0.15,
          "severity": "LOW",
          "matchedRuleIds": ["drift-001"]
        }
      }
    }
  }
}
```

**Healthy condition:** Rule `drift-001` is in `matchedRuleIds` (even if score is low).

### Top Causes of False Negatives

**1. OIDC provider not ingested**
- Symptom: No OIDC provider exists in the graph for account 222.
- Check: Query the graph for OIDC providers:
  ```bash
  kubectl exec -it activable-postgres-0 -- psql -U activable -d activable -c \
    "MATCH (oidc:OIDCProvider {account: '222222222222'}) RETURN oidc.provider_url, oidc.thumbprints;"
  ```
  If empty, the ingest loop didn't read OIDC providers. Check ingestion logs for IAM API errors on OIDC operations.

**2. OIDC drift rule not triggered by current seed script**
- Symptom: Rules fire but no OIDC-specific rule is matched.
- Root cause: The seed script may have an `if false` guard on Scenario 2 if LocalStack v4.7 OIDC support is incomplete.
- Check: Look at the seed script:
  ```bash
  grep -n "if true\|if false" ops/seed/seed-adversarial.sh | grep -A 5 "Scenario 2"
  ```
  If you see `if false`, OIDC is disabled. Update the condition to `if true` to enable it:
  ```bash
  sed -i 's/^if false; then  # Scenario 2/if true; then  # Scenario 2/' ops/seed/seed-adversarial.sh
  ```
  Then re-run the seed script and re-trigger ingestion.

**3. Trust policy conditions are not being evaluated**
- Symptom: OIDC provider exists, but no risk is computed.
- Root cause: The rule engine may not be analyzing OIDC trust policy conditions.
- Check: Query the trust policy and its conditions:
  ```bash
  kubectl exec -it activable-postgres-0 -- psql -U activable -d activable -c \
    "MATCH (oidc:OIDCProvider)-[:HasTrustPolicy]->(tp:TrustPolicy) \
     RETURN oidc.provider_url, tp.condition_key, tp.condition_value;"
  ```
  If the conditions are null or empty, the ingester didn't parse them correctly.

### Top Causes of False Positives

**1. OIDC condition parsing too strict**
- Symptom: All OIDC providers are flagged as drifted, even restrictive ones.
- Root cause: The rule matching logic might not be correctly parsing conditions like `StringLike` vs `StringEquals`.
- Check: Manually inspect a safe OIDC provider's conditions and compare them to the rule's expectations:
  ```bash
  kubectl logs -l app.kubernetes.io/name=activable | grep -i "oidc.*condition" | head -20
  ```

**2. Staging account risk from legitimate cross-account assumption**
- Symptom: Score is high for staging, but the cross-account path is intentional.
- Root cause: The seed script intentionally creates a drifted OIDC policy for testing. If you want to test safe OIDC, tighten the conditions in the seed script.
- Check: Review the trust policy conditions in the seeded role:
  ```bash
  kubectl exec -it activable-postgres-0 -- psql -U activable -d activable -c \
    "MATCH (r:Principal {arn: 'arn:aws:iam::222222222222:role/github-actions-role'})-[:HasTrustPolicy]->(tp:TrustPolicy) \
     RETURN tp.effect, tp.principal, tp.condition_key, tp.condition_value;"
  ```

## Scenario 3: S3 Bucket Policy Principal Boundary Confusion

### What It Detects

An S3 bucket policy that allows `Principal: "*"` (anonymous access) gated only by weak conditions (like `StringEquals: aws:PrincipalOrgID`) can leak data if an attacker is in the same organization. The detection identifies roles with S3 read permissions on buckets with over-broad policies.

**Attack example:** An attacker with `developer-infrastructure-role` in the dev account (111) can read the `org-shared-data` bucket in the secrets account (444) because:
1. The bucket policy allows `Principal: "*"` (anyone in the org)
2. The org-ID condition is met (both accounts in the same org)
3. The developer has identity-based permissions to read S3 objects

### Verify Detection

Query the risk assessment for account 111 and look for S3-related signals:

```bash
curl -s -X POST http://localhost:30080/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ accountRisks(accountId: \"111111111111\") { cascadeRiskScore allSignals { s3DataAccess { score severity matchedRuleIds } } } }"
  }' | jq .
```

Expected output:

```json
{
  "data": {
    "accountRisks": {
      "cascadeRiskScore": 0.42,
      "allSignals": {
        "s3DataAccess": {
          "score": 0.12,
          "severity": "LOW",
          "matchedRuleIds": ["s3-org-id-001"]
        }
      }
    }
  }
}
```

**Healthy condition:** Rule `s3-org-id-001` is in `matchedRuleIds` if the scenario is seeded.

### Top Causes of False Negatives

**1. Bucket policy not ingested**
- Symptom: No bucket policy exists in the graph.
- Check: Query the graph for buckets and their policies:
  ```bash
  kubectl exec -it activable-postgres-0 -- psql -U activable -d activable -c \
    "MATCH (b:S3Bucket {account: '444444444444'})-[:HasPolicy]->(p:BucketPolicy) \
     RETURN b.name, p.effect, p.principal;"
  ```
  If empty, the ingester didn't enumerate S3 bucket policies. Check if the seed script created the bucket:
  ```bash
  aws --endpoint-url http://localhost:30866 s3 ls --region us-east-1
  ```

**2. Identity-based permissions not linked**
- Symptom: The role has S3 read permissions, but they're not linked to the bucket.
- Root cause: The Cypher query for path-finding may not be correctly matching cross-account identity + resource-based policies.
- Check: Manually verify the edge exists:
  ```bash
  kubectl exec -it activable-postgres-0 -- psql -U activable -d activable -c \
    "MATCH (r:Principal {arn: 'arn:aws:iam::111111111111:role/developer-infrastructure-role'})-[:HasPermission]->(:Permission {action: 's3:GetObject'}) \
     RETURN COUNT(*) as perm_count;"
  ```
  If the count is 0, the ingester didn't parse the role's inline policy correctly.

**3. Condition evaluation is missing**
- Symptom: The rule matches but the score is 0.
- Root cause: The bucket policy conditions (e.g., `aws:PrincipalOrgID`) might not be evaluated.
- Check: Query the bucket policy's conditions:
  ```bash
  kubectl exec -it activable-postgres-0 -- psql -U activable -d activable -c \
    "MATCH (b:S3Bucket)-[:HasPolicy]->(p:BucketPolicy) \
     RETURN b.name, p.condition_key, p.condition_value;"
  ```

### Top Causes of False Positives

**1. Bucket policies with explicit account conditions**
- Symptom: A bucket with a restrictive policy (allowing only specific accounts) is flagged as risky.
- Root cause: The rule may not be parsing explicit account conditions in the policy.
- Check: Inspect the bucket policy conditions:
  ```bash
  kubectl logs -l app.kubernetes.io/name=activable | grep -i "bucket.*condition" | head -10
  ```

**2. Cross-account role with no actual data access**
- Symptom: A role is flagged for S3 access even though it has no identity-based permissions.
- Root cause: The rule matching might be using the bucket policy's permissive principal alone, ignoring identity-based restrictions.
- Check: Query the role's actual permissions:
  ```bash
  kubectl exec -it activable-postgres-0 -- psql -U activable -d activable -c \
    "MATCH (r:Principal)-[:HasPermission]->(p:Permission {service: 's3'}) \
     WHERE r.arn CONTAINS 'my-role' \
     RETURN r.arn, p.action, p.resource;"
  ```

## Scenario 4: KMS CreateGrant Lateral Movement

### What It Detects

A role with `kms:Decrypt` on a cross-account KMS key can escalate privileges if the key policy also allows `kms:CreateGrant`. The attacker can create a grant that gives themselves additional permissions (like `kms:GenerateDataKey`) without the key owner's knowledge.

**Attack example:** `application-role` in dev (111) has `kms:Decrypt` on the secrets account's KMS key. The key policy allows the dev account root to call `CreateGrant`. The attacker can assume the application role and create a grant giving themselves `GenerateDataKey`, which can be used to encrypt arbitrary data and extract secrets.

### Verify Detection

Query the risk assessment for account 111 and look for KMS-related signals:

```bash
curl -s -X POST http://localhost:30080/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ accountRisks(accountId: \"111111111111\") { cascadeRiskScore allSignals { kmsEscalation { score severity matchedRuleIds } } } }"
  }' | jq .
```

Expected output (if KMS detection is implemented):

```json
{
  "data": {
    "accountRisks": {
      "cascadeRiskScore": 0.42,
      "allSignals": {
        "kmsEscalation": {
          "score": 0.08,
          "severity": "LOW",
          "matchedRuleIds": ["kms-grant-001"]
        }
      }
    }
  }
}
```

**Healthy condition:** Rule `kms-grant-001` (or similar) is in `matchedRuleIds` if KMS detection is enabled.

### Top Causes of False Negatives

**1. KMS key policy not ingested**
- Symptom: No KMS key exists in the graph.
- Check: Query for KMS keys:
  ```bash
  kubectl exec -it activable-postgres-0 -- psql -U activable -d activable -c \
    "MATCH (k:KMSKey {account: '444444444444'}) RETURN k.key_id, k.region;"
  ```
  If empty, the seed script didn't create the key or the ingester didn't enumerate it.

**2. Cross-account permissions not linked**
- Symptom: The application role has Decrypt permission, but it's not linked to the cross-account key.
- Check: Verify the cross-account edge:
  ```bash
  kubectl exec -it activable-postgres-0 -- psql -U activable -d activable -c \
    "MATCH (r:Principal {arn: 'arn:aws:iam::111111111111:role/application-role'})-[:HasPermission]->(:Permission {service: 'kms', action: 'kms:Decrypt'}) \
     RETURN COUNT(*) as decrypt_count;"
  ```

**3. CreateGrant permission in key policy not parsed**
- Symptom: The key policy is ingested, but the `CreateGrant` permission is missing.
- Root cause: KMS key policy parsing might not handle resource-based permissions correctly.
- Check: Query the key policy directly:
  ```bash
  kubectl exec -it activable-postgres-0 -- psql -U activable -d activable -c \
    "MATCH (k:KMSKey)-[:HasPolicy]->(kp:KMSKeyPolicy) \
     RETURN k.key_id, kp.effect, kp.action, kp.principal;"
  ```

### Top Causes of False Positives

**1. Key policy explicitly denies CreateGrant**
- Symptom: A restrictive KMS key is flagged as allowing grant creation.
- Root cause: Explicit deny statements in the key policy might not be parsed.
- Check: Inspect the key policy in the database:
  ```bash
  kubectl exec -it activable-postgres-0 -- psql -U activable -d activable -c \
    "MATCH (k:KMSKey)-[:HasPolicy]->(kp:KMSKeyPolicy {effect: 'DENY'}) \
     RETURN k.key_id, kp.action, kp.principal;"
  ```

**2. Application role has no encryption usage**
- Symptom: A role with Decrypt is flagged even though it's only reading encrypted data, not creating new encrypted objects.
- Root cause: The rule might not differentiate between read-only and write-capable usage.
- Check: Inspect whether the application role has `kms:GenerateDataKey` or similar write permissions:
  ```bash
  kubectl exec -it activable-postgres-0 -- psql -U activable -d activable -c \
    "MATCH (r:Principal)-[:HasPermission]->(p:Permission {service: 'kms'}) \
     WHERE r.arn CONTAINS 'application-role' \
     RETURN p.action, p.resource;"
  ```

## Scenario 5: (Reserved)

This scenario is reserved for future expansion. No detection rules are currently defined for Scenario 5.

## General Troubleshooting Steps

### 1. Verify Ingestion Completed

Check if the latest ingestion run succeeded:

```bash
# Trigger ingestion and note the run ID
RUN_ID=$(curl -s -X POST http://localhost:30080/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { triggerIngest(provider: \"aws\", regions: [\"us-east-1\"]) { id } }"}' | jq -r '.data.triggerIngest.id')

# Poll until complete
while true; do
  status=$(curl -s -X POST http://localhost:30080/graphql \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{ ingestStatus(runId: \\\"$RUN_ID\\\") { status completedAt resourcesProcessed } }\"}" | jq -r '.data.ingestStatus.status')
  echo "Ingest status: $status"
  [ "$status" = "COMPLETED" ] && break
  sleep 2
done
```

### 2. Check Pod Logs

For ingestion errors:

```bash
kubectl logs -l app.kubernetes.io/name=activable -c activable --tail=200 | grep -i "error\|warning\|ingest"
```

For Postgres errors:

```bash
kubectl logs -l app.kubernetes.io/name=postgres --tail=200 | grep -i "error"
```

For LocalStack errors:

```bash
kubectl logs -l app.kubernetes.io/component=localstack --tail=200 | grep -i "error\|routing"
```

### 3. Re-seed LocalStack

If you suspect the seed script didn't run correctly, re-seed:

```bash
export AWS_ENDPOINT_URL="http://localhost:30866"  # or http://activable-localstack:4566 if port-forwarding
bash ops/seed/seed-adversarial.sh
```

Then re-trigger ingestion.

### 4. Check Service Connectivity

Verify the GraphQL endpoint is reachable:

```bash
curl -sf http://localhost:30080/healthz
```

Verify LocalStack is reachable from the pod:

```bash
kubectl exec -it activable-0 -- curl -sf http://activable-localstack:4566/health
```

### 5. Inspect the Graph Directly

For detailed debugging, query the Postgres database directly:

```bash
# Count nodes and edges
kubectl exec -it activable-postgres-0 -- psql -U activable -d activable -c \
  "MATCH (n) RETURN labels(n)[0] as label, COUNT(*) as count GROUP BY label ORDER BY count DESC;"

# List all principals in a specific account
kubectl exec -it activable-postgres-0 -- psql -U activable -d activable -c \
  "MATCH (p:Principal {account: '111111111111'}) RETURN p.arn, p.type LIMIT 20;"

# List all edges from a principal
kubectl exec -it activable-postgres-0 -- psql -U activable -d activable -c \
  "MATCH (p:Principal {arn: 'arn:aws:iam::111111111111:role/developer-role'})-[e]->(n) \
   RETURN type(e) as edge_type, labels(n)[0] as target_label, COUNT(*) as count GROUP BY edge_type, target_label;"
```

## Alert Thresholds

Use these thresholds when alerting on detection engine health:

| Metric | Alert threshold | Severity |
|---|---|---|
| Account 111 `cascadeRiskScore` | < 0.35 | WARN (possible false negative) |
| Account 111 `cfEscalation.score` | < 0.30 | WARN (CF rule not firing) |
| Account 222 `cascadeRiskScore` | < 0.35 | WARN (OIDC or other rules not firing) |
| Account 333 `cascadeRiskScore` | > 0.20 | WARN (prod account should be low-risk) |
| Ingestion run time | > 60s | INFO (slow ingestion, check Postgres) |
| Ingest failure rate (rolling 24h) | > 5% | WARN (intermittent ingestion issues) |

## Escalation Path

If the troubleshooting steps above don't resolve the issue:

1. **Check the system architecture:** Review [`docs/system-architecture.md`](../system-architecture.md) for the complete data flow.
2. **Inspect rule definitions:** Read the YAML files in `crates/activable-risk/config/escalation-paths/bundled/` to understand rule matching logic.
3. **Review recent commits:** Check git log for recent changes to the ingester, graph, or risk engine:
   ```bash
   git log --oneline -20 -- crates/activable-ingest crates/activable-graph crates/activable-risk
   ```
4. **File a bug:** If you identify a reproducible issue, file a bug with:
   - Steps to reproduce
   - Pod logs (sanitized of credentials)
   - The output of `make probe-accounts`
   - The failing rule or scenario
