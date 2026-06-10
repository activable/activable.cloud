# Seeding the Test Environment

This guide walks a new engineer through setting up a local development environment with LocalStack, seeding it with adversarial test scenarios, triggering ingestion, and verifying that the detection engine is working.

## Prerequisites

Before starting, ensure you have:

- **Docker Desktop** with Kubernetes enabled
  - Settings > Kubernetes > Enable Kubernetes
  - Allocate at least 4 CPU cores and 4GB RAM to Docker
- **kubectl** — comes with Docker Desktop, verify with `kubectl version`
- **Helm 3+** — install with `brew install helm` (macOS) or your package manager
- **rtk** (token-optimized CLI) — install with `brew install rust-token-killer` or [from source](https://github.com/reachingforthejack/rtk)
- **zig v0.14** — required for cross-compilation: `brew install zig@0.14`
- **sccache** (optional but recommended for faster rebuilds) — `brew install sccache`
- **rustup** with aarch64-unknown-linux-gnu target
  ```bash
  rustup target add aarch64-unknown-linux-gnu
  ```
- **jq** — for parsing JSON responses: `brew install jq`

## Step 1: Verify Prerequisites

Run the setup command to check all dependencies:

```bash
make setup
```

This installs pre-commit hooks and validates your environment. If any tool is missing, the output will tell you which one to install.

## Step 2: Build the Docker Image

Build the Activable GraphQL server Docker image for your local Kubernetes:

```bash
docker build -t activable-server:dev -f ops/docker/Dockerfile .
```

This creates a local image tagged `activable-server:dev` that Kubernetes will use without pulling from a registry.

## Step 3: Deploy to Kubernetes

Deploy the entire stack (Postgres+AGE, LocalStack v4.7, Activable GraphQL server) using Helm:

```bash
helm upgrade --install activable ops/helm/activable \
  -f ops/helm/activable/values-local.yaml \
  --wait --timeout 300s
```

This command:
- Installs a Postgres+AGE StatefulSet (for the knowledge graph)
- Installs a LocalStack v4.7 Deployment (AWS emulator with multi-account support)
- Installs the Activable GraphQL server pod
- Waits up to 5 minutes for all pods to become ready

Verify the deployment is healthy:

```bash
kubectl get pods -l app.kubernetes.io/instance=activable
```

You should see three pods in the `Running` state:
- `activable-postgres-0` (StatefulSet)
- `activable-localstack-XXXXX` (Deployment)
- `activable-XXXXX` (Deployment)

Check service endpoints:

```bash
kubectl get svc -l app.kubernetes.io/instance=activable
```

## Step 4: Understand the Test Scenario Accounts

The seed script creates 4 AWS accounts in LocalStack to emulate a multi-tenant environment:

| Account ID | Role | Purpose |
|---|---|---|
| `111111111111` | Development | CloudFormation escalation, S3 access, Lambda execution |
| `222222222222` | Staging | OIDC federation setup, cross-account deployment |
| `333333333333` | Production | Cross-account secrets management, restricted access |
| `444444444444` | Secrets/Data Lake | Shared resources (S3 buckets, KMS keys); no IAM principals |

Each account is routed via LocalStack's multi-account model: the `AWS_ACCESS_KEY_ID` environment variable is set to the 12-digit account ID, and LocalStack routes IAM operations to that account's namespace.

## Step 5: Seed LocalStack with Adversarial Scenarios

Run the seed script to populate LocalStack with test IAM resources and relationships:

```bash
export AWS_ENDPOINT_URL="http://localhost:30866"
bash ops/seed/seed-adversarial.sh
```

**Note:** The endpoint URL depends on how LocalStack is exposed. In Kubernetes:
- If you port-forward: `kubectl port-forward svc/activable-localstack 30866:4566`
- Then use `http://localhost:30866`

Or if LocalStack is exposed as a NodePort service, check:
```bash
kubectl get svc activable-localstack -o jsonpath='{.spec.ports[0].nodePort}'
```

The script creates 5 adversarial scenarios:

### Scenario 1: CloudFormation Service Role Trap
**Accounts involved:** 111 (dev), 222 (staging)

**Entities created:**
- `developer-role` (dev) with permissions to run CloudFormation, S3 read, and assume cross-account role
- `cf-deploy-production-role` (dev) with trust policy allowing CloudFormation and staging account to assume it
- `cross-account-deployer` (staging) that can be assumed by the developer role

**Detection focus:** An attacker with `developer-role` can pass `cf-deploy-production-role` to CloudFormation and execute templates with elevated permissions.

### Scenario 2: GitHub Actions OIDC Configuration Drift
**Accounts involved:** 222 (staging), 333 (production)

**Entities created:**
- OIDC provider (`token.actions.githubusercontent.com`) in staging account
- `github-actions-role` that assumes the OIDC provider with a drifted (overly permissive) trust policy
- `codepipeline-deploy-role` (staging) that can be assumed by the GitHub Actions role
- `codepipeline-prod-deployer` (prod) that can be assumed by the staging deployer

**Detection focus:** A federated identity can assume roles across multiple accounts via a drifted OIDC trust policy.

### Scenario 3: S3 Bucket Policy Principal Boundary Confusion
**Accounts involved:** 111 (dev), 444 (secrets/data-lake)

**Entities created:**
- `developer-infrastructure-role` (dev) with S3 read permissions on the shared bucket
- `org-shared-data` bucket (secrets account) with a permissive bucket policy allowing `Principal: "*"` gated by org-ID condition

**Detection focus:** A principal with bucket read permissions may access data outside their account if the bucket policy allows cross-account access via a weak condition.

### Scenario 4: KMS CreateGrant Lateral Movement
**Accounts involved:** 111 (dev), 444 (secrets/data-lake)

**Entities created:**
- `application-role` (dev) with Decrypt permission on the secrets account's KMS key
- KMS key (secrets account) with a key policy allowing the dev account root to create grants

**Detection focus:** An attacker with Decrypt permission on a KMS key can use `CreateGrant` to give themselves more powerful permissions (e.g., `GenerateDataKey`).

## Step 6: Verify Seeding Completed Successfully

The seed script outputs a summary. Example output:

```
=== Seeding Complete ===

Development Account (111111111111):
  Roles: 4
    - developer-role (Scenario 1)
    - cf-deploy-production-role (Scenario 1)
    - developer-infrastructure-role (Scenario 3)
    - application-role (Scenario 4)
  Inline Policies: 6

Staging Account (222222222222):
  Roles: 3
    - cross-account-deployer (Scenario 1)
    - github-actions-role (Scenario 2)
    - codepipeline-deploy-role (Scenario 2)
  Inline Policies: 4
  OIDC Providers: 1
    - token.actions.githubusercontent.com (Scenario 2)

Production Account (333333333333):
  Roles: 1
    - codepipeline-prod-deployer (Scenario 2)
  Inline Policies: 1

Secrets Account (444444444444):
  Roles: 0
  S3 Buckets: 1
    - org-shared-data (Scenario 3)
  KMS Keys: 1
    - (Scenario 4)

All scenarios are idempotent and can be re-run safely.
```

If the seed script fails, check the error message. Common issues:

- **LocalStack not ready:** The script waits 60 seconds for LocalStack to respond to IAM API calls. If it times out, LocalStack may still be pulling the image. Wait another 30 seconds and re-run.
- **Multi-account routing not working:** Check that `AWS_ACCESS_KEY_ID` is set correctly to each account ID. The seed script's `aws_in_account()` helper function sets this automatically.
- **Network connectivity:** Verify the endpoint URL is correct: `curl -s http://localhost:30866/health | jq .` should return a 200 OK.

## Step 7: Trigger Ingestion

Ingestion is triggered via the GraphQL API. The Activable server runs an ingest pipeline that:
1. Connects to LocalStack using the configured accounts
2. Enumerates all IAM resources (roles, policies, OIDC providers)
3. Writes them to the Postgres+AGE graph database
4. Computes risk scores based on escalation rules

Trigger ingestion via GraphQL mutation:

```bash
curl -s -X POST http://localhost:30080/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "mutation { triggerIngest(provider: \"aws\", regions: [\"us-east-1\"]) { id status startedAt } }"
  }' | jq .
```

Example response:

```json
{
  "data": {
    "triggerIngest": {
      "id": "run-20260525-160423",
      "status": "RUNNING",
      "startedAt": "2026-05-25T16:04:23Z"
    }
  }
}
```

Note the run ID (e.g., `run-20260525-160423`) for polling status.

## Step 8: Wait for Ingestion to Complete

Poll the ingest status query until the run completes:

```bash
RUN_ID="run-20260525-160423"  # Replace with the ID from Step 7
while true; do
  curl -s -X POST http://localhost:30080/graphql \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{ ingestStatus(runId: \\\"$RUN_ID\\\") { status completedAt resourcesProcessed } }\"}" | jq .
  sleep 2
done
```

Watch for `status: "COMPLETED"` and `resourcesProcessed: <number>`. The ingestion typically takes 10-30 seconds depending on the number of resources.

Alternative: Check the pod logs for progress:

```bash
kubectl logs -f -l app.kubernetes.io/name=activable --tail=50
```

## Step 9: Verify Detection Engine is Working

Run the `make probe-accounts` target to query the risk scores for all four seeded accounts:

```bash
make probe-accounts GRAPHQL_URL=http://localhost:30080/graphql
```

This executes a GraphQL query for each account:

```graphql
{
  accountRisks(accountId: "111111111111") {
    cascadeRiskScore
    cascadeSeverity
    allSignals {
      cfEscalation {
        score
        severity
        matchedRuleIds
      }
    }
  }
}
```

Expected output (healthy system):

```
=== account 111111111111 ===
{
  "data": {
    "accountRisks": {
      "cascadeRiskScore": 0.4194,
      "cascadeSeverity": "MEDIUM",
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

=== account 222222222222 ===
{
  "data": {
    "accountRisks": {
      "cascadeRiskScore": 0.4332,
      "cascadeSeverity": "MEDIUM",
      "allSignals": {
        "cfEscalation": {
          "score": 0.43,
          "severity": "MEDIUM",
          "matchedRuleIds": [
            "cf-passrole-001",
            "lambda-001"
          ]
        }
      }
    }
  }
}

=== account 333333333333 ===
{
  "data": {
    "accountRisks": {
      "cascadeRiskScore": 0.1003,
      "cascadeSeverity": "INFO",
      "allSignals": {
        "cfEscalation": null
      }
    }
  }
}

=== account 444444444444 ===
{
  "data": {
    "accountRisks": null
  }
}
```

**Interpretation:**

- **Account 111 (dev):** Score 0.42, rules `cf-passrole-001` + `iam-update-trust-001` + `lambda-001` matched. This account is risky because the developer role can pass the CF role to CloudFormation and escalate.
- **Account 222 (staging):** Score 0.43, rules `cf-passrole-001` + `lambda-001` matched. Staging mirrors some of dev's escalation paths.
- **Account 333 (prod):** Score 0.10, `cfEscalation: null`. Production account has minimal risk because the deployer role is constrained.
- **Account 444 (secrets):** `accountRisks: null`. No IAM principals in this account (by design); no risk assessment available.

If the scores are 0 or missing, ingestion may not have completed. Wait a few more seconds and retry.

## Step 10: Explore the Graph via GraphQL

Use the GraphQL playground to explore the knowledge graph. Open your browser to:

```
http://localhost:30080/
```

This opens the Apollo GraphQL Playground. Example queries:

**Find a principal:**

```graphql
{
  findNode(label: "Principal", id: "arn:aws:iam::111111111111:role/developer-role") {
    id
    label
    properties
  }
}
```

**Walk edges from a principal (2 hops):**

```graphql
{
  walkEdges(
    start: "arn:aws:iam::111111111111:role/developer-role"
    edgeTypes: ["CanAssume", "HasPermission"]
    direction: "OUTGOING"
    depth: 2
  ) {
    id
    label
  }
}
```

**Find a path between two principals:**

```graphql
{
  pathFinder(
    start: "arn:aws:iam::111111111111:role/developer-role"
    end: "arn:aws:iam::111111111111:role/cf-deploy-production-role"
    edgePattern: ["CanAssume", "HasPermission"]
    maxHops: 3
  ) {
    nodes {
      id
      label
    }
    edges {
      type
    }
  }
}
```

## Step 11: Troubleshooting

### Pods are in `CrashLoopBackOff`

Check the pod logs:

```bash
kubectl logs -l app.kubernetes.io/instance=activable --all-containers=true --previous
```

Common causes:

- **Postgres not ready:** AGE (Apache Age) takes 20-30 seconds to initialize. Wait longer before deploying the GraphQL server.
- **LocalStack not ready:** LocalStack needs to be healthy before the ingester connects. Check its logs:
  ```bash
  kubectl logs -l app.kubernetes.io/component=localstack
  ```

### LocalStack routes to `000000000000` instead of requested account

This indicates the multi-account routing is not working. Verify:

1. LocalStack version is v4.7 or higher:
   ```bash
   kubectl get pod -l app.kubernetes.io/component=localstack -o jsonpath='{.items[0].spec.containers[0].image}'
   ```

2. Re-run the seed script with explicit endpoint URL:
   ```bash
   export AWS_ENDPOINT_URL="http://activable-localstack:4566"  # Use K8s internal DNS
   bash ops/seed/seed-adversarial.sh
   ```

3. Check LocalStack's startup logs for multi-account initialization:
   ```bash
   kubectl logs -l app.kubernetes.io/component=localstack | grep -i "multi-account\|routing"
   ```

### AGE label table not found (first boot warning)

The first ingest run may log warnings like:

```
ERROR neo4j_mapper: Failed to execute statement: ERROR: label table "RoleLabel" does not exist (SQLSTATE 42P01)
```

This is expected on first boot — AGE's label cache initializes lazily. Re-run ingestion after the first attempt succeeds. The warnings will disappear on subsequent runs.

### Ingestion never completes

Check if the GraphQL server is stuck waiting for Postgres:

```bash
kubectl logs -l app.kubernetes.io/name=activable | tail -50 | grep -i "postgres\|pool\|timeout"
```

If you see connection pool errors, the Postgres pod may not be responding. Restart it:

```bash
kubectl delete pod -l app.kubernetes.io/name=postgres
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=postgres --timeout=60s
```

Then re-trigger ingestion.

## Step 12: Clean Up

To stop the local environment and preserve data (for the next session):

```bash
helm uninstall activable
```

To reset everything (delete data, PVCs, start fresh):

```bash
make dev-reset
```

## Next Steps

- [Run the end-to-end adversarial test](./runbook-detection-failures.md) to validate all 5 scenarios are detected.
- [Learn how to add new detection rules](../development/rule-authoring-guide.md).
- Review the [system architecture](../system-architecture.md) to understand how the ingester, graph, and risk engine interact.
