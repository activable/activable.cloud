# Rule Authoring Guide

This guide explains how to add a new privilege escalation detection rule to the Activable risk engine.

## Overview

A detection rule is a YAML file that defines:
1. **Rule metadata** — ID, name, severity category
2. **Permission requirements** — what IAM actions trigger the rule
3. **Match conditions** — optional prerequisites (admin action, cross-account access)
4. **Score boost** — how much risk this rule contributes

Rules are bundled at compile time and loaded by the risk engine to identify privilege escalation paths in IAM configurations.

## Rule File Location

Rule files are stored in:

```
crates/activable-risk/config/escalation-paths/bundled/
```

**Naming convention:** `{category}-{number}.yaml`

Examples:
- `cf-passrole-001.yaml` — CloudFormation PassRole escalation
- `iam-update-trust-001.yaml` — Trust policy hijacking
- `s3-org-id-001.yaml` — S3 bucket policy overly broad access
- `lambda-001.yaml` — Lambda PassRole escalation

## Rule File Structure

Here is a complete example rule (based on an existing rule in the codebase):

```yaml
id: cf-passrole-001
name: "iam:PassRole + cloudformation:CreateStack privilege escalation"
category: passrole
services:
  - iam
  - cloudformation
permissions:
  all_of:
    - permission: "iam:PassRole"
      resourceConstraints: "Can pass an IAM role to CloudFormation"
    - any_of:
        - permission: "cloudformation:CreateStack"
          resourceConstraints: ""
        - permission: "cloudformation:UpdateStack"
          resourceConstraints: ""
description: |
  Principal with iam:PassRole AND any cloudformation:* action that can execute
  a stack template can escalate to the privileges of the passed role.
  CloudFormation will execute the template with the role's permissions,
  allowing privilege escalation if the target role has elevated permissions.

  Reference: HackingTheCloud, Cloudsplaining privilege escalation patterns.
```

### Field Definitions

#### `id` (required, string)

Unique identifier for the rule. Used in GraphQL responses and logs.

Format: lowercase letters, digits, and hyphens. Convention: `{category}-{number}` where number is zero-padded (e.g., `001`, `002`).

#### `name` (required, string)

Human-readable description of the escalation path. Used in UI and reports.

Keep it under 100 characters for readability in tables and alerts.

#### `category` (required, string)

Severity classification. Controls the score boost applied when the rule matches.

Valid values:
- `cascade` — Critical: direct admin path (score boost ~0.15)
- `self-escalation` — Critical: direct privilege gain (score boost ~0.15)
- `passrole` — High: PassRole combined with action (score boost ~0.10)
- `new-passrole` — High: PassRole enabling new principal (score boost ~0.10)
- `credential-access` — Medium: can gain new credentials (score boost ~0.05)
- `new-principal` — Medium: can create new principals (score boost ~0.05)
- `data-access` — Low: can access sensitive data (score boost ~0.03)
- (custom) — Lowest: other (score boost ~0.02)

#### `services` (required, array of strings)

AWS services involved in the escalation. Used for filtering and dashboards.

Examples: `iam`, `lambda`, `ec2`, `s3`, `kms`, `cloudformation`, `sts`

#### `permissions` (required, object or null)

The permission structure that must be present to trigger the rule. Supports complex boolean logic.

**Format options:**

**Option 1: Single permission (implicit AllOf)**
```yaml
permissions:
  - permission: "iam:UpdateAssumeRolePolicy"
    resourceConstraints: ""
```

**Option 2: AllOf (all conditions required)**
```yaml
permissions:
  all_of:
    - permission: "iam:PassRole"
      resourceConstraints: "Can pass an IAM role"
    - permission: "cloudformation:CreateStack"
      resourceConstraints: ""
```

**Option 3: AnyOf (at least one condition required)**
```yaml
permissions:
  any_of:
    - permission: "lambda:InvokeFunction"
    - permission: "lambda:InvokeAsync"
```

**Option 4: Nested logic**
```yaml
permissions:
  all_of:
    - permission: "iam:PassRole"
      resourceConstraints: ""
    - any_of:
        - permission: "cloudformation:CreateStack"
        - permission: "cloudformation:UpdateStack"
        - permission: "cloudformation:ExecuteChangeSet"
```

**Option 5: No permissions (cascade rules)**
```yaml
permissions: {}
```

Used for rules that represent structural relationships, not direct permissions.

**Each permission object contains:**

- `permission` (required) — IAM action in the format `service:Action` (e.g., `iam:PassRole`, `kms:CreateGrant`)
- `resourceConstraints` (optional, string) — Human-readable note about resource scope (e.g., "Can pass roles matching arn:aws:iam::*:role/cf-*")

#### `prerequisites` (optional, object)

Conditions that must be true for the escalation to succeed. Used for more nuanced rule triggering.

**Fields:**
- `admin` — Actions that require a role to have admin permissions
- `lateral` — Actions that require specific role trust policies

**Example:**
```yaml
prerequisites:
  admin:
    - "A role must exist that trusts lambda.amazonaws.com"
    - "The role must have admin permissions"
  lateral:
    - "A role must exist that trusts lambda.amazonaws.com"
```

#### `description` (optional, string)

Detailed explanation of the escalation path, attack examples, and references.

Use multi-line YAML syntax (`|`) for readability:

```yaml
description: |
  Principal with iam:PassRole AND any cloudformation:* action that can execute
  a stack template can escalate to the privileges of the passed role.
  CloudFormation will execute the template with the role's permissions,
  allowing privilege escalation if the target role has elevated permissions.

  Attack example: Developer with CloudFormation write can assume a role with
  admin permissions, then use CloudFormation to create new roles and policies.

  Reference: HackingTheCloud, Cloudsplaining, AWS privilege escalation docs.
```

#### `trigger` (optional, object)

Advanced: Cascade trigger conditions for multi-hop escalations. Leave empty for most rules.

## Step-by-Step: Adding a New Rule

### Step 1: Identify the Escalation Path

Document the escalation path in plain English:

**Example:** A principal with `s3:PutObject` on a bucket with a Lambda notification can trigger arbitrary Lambda functions.

### Step 2: Determine Permissions Required

List the IAM permissions needed to execute the attack:

1. **Identity-based permissions:** What does the principal need?
   - `s3:PutObject` on the target bucket

2. **Resource-based policies:** What do the target resources allow?
   - The bucket has a notification policy pointing to a Lambda function
   - The Lambda function's resource policy allows the bucket to invoke it

### Step 3: Identify the Category and Services

- **Category:** Determine severity: is this admin access, credential access, or data access?
  - In this example: `credential-access` (the attacker can trigger arbitrary code execution)
- **Services:** List all AWS services involved
  - `["s3", "lambda"]`

### Step 4: Create the YAML File

Create a new file in `crates/activable-risk/config/escalation-paths/bundled/`:

```bash
touch crates/activable-risk/config/escalation-paths/bundled/s3-lambda-trigger-001.yaml
```

Write the rule definition:

```yaml
id: s3-lambda-trigger-001
name: "s3:PutObject + Lambda notification trigger"
category: credential-access
services:
  - s3
  - lambda
permissions:
  all_of:
    - permission: "s3:PutObject"
      resourceConstraints: "Can write to bucket with Lambda notifications"
    - permission: "lambda:InvokeFunction"
      resourceConstraints: "Bucket notification can invoke the function"
description: |
  Principal with s3:PutObject on a bucket that has Lambda notifications configured
  can trigger arbitrary Lambda functions by uploading objects.

  Attack example: Upload a malicious file to the bucket, which automatically
  invokes a Lambda function. If the Lambda has elevated permissions, the attacker
  gains those permissions.

  Reference: AWS S3 event notifications, Lambda permissions.
```

### Step 5: Test the Rule with Unit Tests

Add a unit test to verify the rule matches correctly. Tests are in:

```
crates/activable-risk/src/
```

Create or update a test that:
1. Creates a Principal with the required permissions
2. Adds them to the graph
3. Runs the rule engine
4. Asserts the rule matched with the expected score

Example test structure:

```rust
#[test]
fn test_rule_s3_lambda_trigger_001() {
    let mut rule_loader = RuleLoader::new();
    let rules = rule_loader.load_all_rules().expect("Failed to load rules");
    
    // Find the rule
    let rule = rules.iter().find(|r| r.id == "s3-lambda-trigger-001")
        .expect("Rule not found");
    
    // Verify rule properties
    assert_eq!(rule.category, "credential-access");
    assert!(rule.services.contains(&"s3".to_string()));
    assert!(rule.services.contains(&"lambda".to_string()));
    
    // (Integration test: simulate principal with both permissions, assert matching)
}
```

For now, it's sufficient to verify the YAML is valid and loads without errors:

```bash
cargo test --lib activable-risk
```

### Step 6: Add a Seed Entity (Optional but Recommended)

Update the seed script (`deploy/scripts/seed-adversarial.sh`) to create a test entity that triggers the new rule.

For example, if the rule detects a risk in S3 bucket notifications:

```bash
# (In seed-adversarial.sh, after other scenario seeds)

echo "--- Scenario N: S3 Lambda Trigger Example ---"

# Create bucket with Lambda notification
aws_in_account "$DEV_ACCOUNT" s3 mb "s3://lambda-notification-bucket" 2>/dev/null || true

# Create Lambda function
LAMBDA_ARN=$(aws_in_account "$DEV_ACCOUNT" lambda create-function \
    --function-name "notification-processor" \
    --runtime "python3.11" \
    --role "arn:aws:iam::$DEV_ACCOUNT:role/application-role" \
    --handler "index.handler" \
    --zip-file "..." \
    --query 'FunctionArn' --output text)

# Add bucket notification
aws_in_account "$DEV_ACCOUNT" s3api put-bucket-notification-configuration \
    --bucket "lambda-notification-bucket" \
    --notification-configuration "{
  \"LambdaFunctionConfigurations\": [
    {
      \"LambdaFunctionArn\": \"$LAMBDA_ARN\",
      \"Events\": [\"s3:ObjectCreated:*\"]
    }
  ]
}"

echo "✓ Scenario N complete: S3 bucket with Lambda notifications"
```

Then, update the ingest pipeline to enumerate bucket notifications. (This would involve changes to `crates/activable-ingest/src/`, which is out of scope for this guide.)

### Step 7: Add an E2E Test Assertion (Optional but Recommended)

Update the end-to-end adversarial test (`crates/activable-graphql/tests/e2e_adversarial.rs`, which a sibling sub-agent is creating) to assert the new rule fires for the seeded entity.

Example:

```rust
#[test]
#[ignore]  // run only when E2E_TEST_URL is set
fn e2e_adversarial_scenarios() {
    let env = E2eEnvironment::from_env();
    env.reset_graph();
    env.run_seed_script();
    let run_id = env.trigger_ingest();
    env.wait_for_ingest_complete(run_id, 60.seconds());

    // ... existing assertions ...

    // New assertion for s3-lambda-trigger-001
    let account_111 = env.account_risks("111111111111");
    assert!(
        account_111.all_signals.s3_lambda_trigger.matched_rule_ids.contains(&"s3-lambda-trigger-001".to_string()),
        "s3-lambda-trigger-001 should fire for account 111"
    );
}
```

### Step 8: Rebuild and Deploy

Rebuild the Rust workspace to include the new rule:

```bash
make build-linux
make deploy-dev
```

The new rule is now compiled into the binary and will be loaded when the server starts.

### Step 9: Verify the Rule Fires

Query the GraphQL endpoint to confirm the rule is firing:

```bash
# Trigger ingestion
curl -s -X POST http://localhost:30080/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { triggerIngest(provider: \"aws\", regions: [\"us-east-1\"]) { id } }"}' | jq .

# Wait for completion, then query
curl -s -X POST http://localhost:30080/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ findings(minSeverity: \"LOW\") { cascadeRiskScore allSignals { s3LambdaTrigger { matchedRuleIds } } } }"
  }' | jq .
```

Verify `s3-lambda-trigger-001` appears in the `matchedRuleIds` for the expected account.

## Example: Complete Rule

Here is a complete, real-world rule from the codebase:

```yaml
id: iam-update-trust-001
name: "iam:UpdateAssumeRolePolicy trust-policy hijack"
category: new-passrole
services:
  - iam
permissions:
  required:
    - permission: "iam:UpdateAssumeRolePolicy"
      resourceConstraints: "Can rewrite trust policy on a role"
description: |
  Principal can rewrite the trust policy of any role they have permission on.
  Used as a privilege escalation primitive when combined with other findings
  (e.g., a drifted OIDC trust policy that is too loose).

  Attack: Rewrite the trust policy to allow the attacker's role to assume
  a privileged role, effectively bypassing intended access controls.
```

## Rule Matching Logic

The risk engine uses the following logic to match a rule:

1. **Permission matching:**
   - For each principal in the graph, enumerate all permissions (identity-based + cross-account resource-based)
   - Check if the principal's permissions satisfy the rule's `permissions` requirements
   - If the rule has `all_of`: all conditions must be true
   - If the rule has `any_of`: at least one condition must be true
   - Nested logic is evaluated recursively

2. **Prerequisite checking (optional):**
   - If the rule specifies prerequisites, verify they are met by querying the graph
   - Example: "A Lambda execution role must exist in the same account"

3. **Score calculation:**
   - If the rule matches, add a score boost based on the rule's category
   - Combine all matching rules into a cascade risk score for the principal

## Debugging Rule Matching

### Verify Rule Loads

Check that the rule is loaded at startup:

```bash
kubectl logs -l app.kubernetes.io/name=activable | grep "Loading rule\|rule_id" | grep "s3-lambda-trigger"
```

### Verify Rule Matches Manually

Query the graph to inspect a principal's permissions:

```bash
# List all permissions for a principal
kubectl exec -it activable-postgres-0 -- psql -U activable -d activable -c \
  "MATCH (p:Principal {arn: 'arn:aws:iam::111111111111:role/developer-role'})-[:HasPermission]->(perm:Permission) \
   RETURN perm.service, perm.action ORDER BY perm.action;"
```

Cross-reference against the rule's `permissions` requirements. If all required permissions are present, the rule should match.

### Check Rule Firing in Logs

Inspect detailed risk scoring logs:

```bash
kubectl logs -l app.kubernetes.io/name=activable | grep -i "rule.*match\|escalation.*match\|s3-lambda-trigger" | tail -20
```

## Best Practices

1. **One escalation path per rule.** Don't overload a single rule with multiple unrelated attack vectors.
2. **Use specific permissions.** `iam:PassRole` is more specific than `iam:*`. More specific rules are easier to tune.
3. **Document the reference.** Link to HackingTheCloud, Cloudsplaining, AWS docs, or a CVE if applicable.
4. **Test with realistic scenarios.** Seed the rule with a realistic entity in the test environment.
5. **Avoid over-broad matching.** If a rule matches too many entities that aren't actually risky, consider adding resource constraints or prerequisites.
6. **Keep categories consistent.** Use the predefined categories; don't invent new ones without discussion.

## Rule Ideas for Future Implementation

These rules are recognized but not yet implemented:

- **`assume-role-with-saml-001`** — Assume role via SAML federation with drifted conditions
- **`ec2-instance-profile-001`** — EC2 instance with overly permissive instance profile
- **`dynamodb-stream-001`** — DynamoDB stream with Lambda processor that has elevated permissions
- **`sns-sqs-wildcard-001`** — SNS/SQS topics with resource policies allowing `Principal: "*"`
- **`secrets-manager-001`** — Secrets Manager resource policy allows cross-account read

If you want to implement any of these, follow the steps above and open a pull request.

## File Locations and Ownership

| File | Purpose | Edit? |
|---|---|---|
| `crates/activable-risk/config/escalation-paths/bundled/*.yaml` | Rule definitions | Yes — add new rules here |
| `crates/activable-risk/src/rule_loader.rs` | Rule loading logic | No — rule format is defined here |
| `crates/activable-risk/src/rule_engine.rs` | Rule matching engine | No — don't modify matching logic without discussion |
| `deploy/scripts/seed-adversarial.sh` | Test scenario seed | Yes — add test entities for your rule |
| `crates/activable-graphql/tests/e2e_adversarial.rs` | E2E test assertions | Yes — add assertions for your rule |
| `docs/operations/runbook-detection-failures.md` | On-call runbook | Yes — document your rule's failure modes |

## See Also

- [Seeding the test environment](../operations/seeding-test-environment.md) — how to seed test entities
- [Detection failures runbook](../operations/runbook-detection-failures.md) — how to debug rule matching
- [System architecture](../system-architecture.md) — how the rule engine integrates with the ingester and graph
