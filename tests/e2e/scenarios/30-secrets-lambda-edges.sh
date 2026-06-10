#!/bin/bash

################################################################################
# scenarios/30-secrets-lambda-edges.sh
#
# Scenario: Secrets Manager + Lambda access-edge assertions (seeded data)
#
# Requires: adversarial seed applied (seed.sh) AND an ingest of the secrets
# account (444444444444) completed. Asserts the ingestion enrichers actually
# produced the access-edge classes in the graph, through the public GraphQL
# endpoint:
#
#   1. Full permission path resolves:
#      Principal(secrets-reader-role) -HasEffectivePermission-> Permission
#        -ActsOn-> Secret  (specific-ARN IAM grant joined by the rule engine)
#   2. Secret -EncryptedBy-> KmsKey (customer CMK; AWS-managed sentinel separately)
#   3. Secret -AllowsAccessFrom-> external cross-account Principal (999...:root)
#   4. Lambda function Resource node -AllowsAccessFrom-> Principal(s)
#      (resource policy: service + cross-account invoke grants)
#
# Zero-edge policy: every assertion requires >0 results. An empty walk is a
# FAILURE (silent-pass prevention), never a skip.
#
# Usage:
#   ./30-secrets-lambda-edges.sh
#
# Returns: 0 if all assertions pass, 1 if any fail
#
################################################################################

set -euo pipefail

# Source config and lib from parent directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/config.sh"
source "$SCRIPT_DIR/lib.sh"

echo "========================================"
echo "Scenario 30: Secrets Manager + Lambda Access Edges"
echo "========================================"
echo ""

# Reset counters
TESTS_PASSED=0
TESTS_FAILED=0

READER_ROLE_ARN="arn:aws:iam::${ACCOUNT_SECRETS}:role/secrets-reader-role"
EXTERNAL_ROOT_ARN="arn:aws:iam::999999999999:root"
LAMBDA_FUNCTION_ARN="arn:aws:lambda:us-east-1:${ACCOUNT_SECRETS}:function:data-processor"

# ============================================================================
# Test 1: Full permission path Principal -> Permission -> ActsOn -> Secret
#
# Walked as two chained single-edge-type hops (AGE does not support edge-label
# alternation, so each hop is asserted explicitly — which also proves each edge
# class independently).
# ============================================================================
echo "Test 1: Permission path to Secret (HasEffectivePermission, then ActsOn)"

# Hop 1: Principal -[HasEffectivePermission]-> Permission
HOP1_RESPONSE=$(gql '
  query {
    walkEdges(
      start: "'"$READER_ROLE_ARN"'",
      edgeTypes: ["HasEffectivePermission"],
      direction: "OUTGOING",
      depth: 10
    ) {
      id
      label
    }
  }
')

HOP1_ERRORS=$(echo "$HOP1_RESPONSE" | jq -r '.errors[]?.message' 2>/dev/null || echo "")
if [[ -z "$HOP1_ERRORS" ]]; then
    log_pass "walkEdges HasEffectivePermission hop executed without errors"
else
    log_fail "walkEdges HasEffectivePermission hop returned errors: $HOP1_ERRORS"
fi

PERMISSION_IDS=$(echo "$HOP1_RESPONSE" | jq -r '[.data.walkEdges[]? | select(.label == "Permission")][].id')
PERMISSION_COUNT=$(echo "$HOP1_RESPONSE" | jq '[.data.walkEdges[]? | select(.label == "Permission")] | length')
assert_gt "$PERMISSION_COUNT" "0" "Principal has HasEffectivePermission edge(s) to Permission node(s)"

# Hop 2: each Permission -[ActsOn]-> Secret; collect any Secret targets
SECRET_ID=""
for perm_id in $PERMISSION_IDS; do
    HOP2_RESPONSE=$(gql '
      query {
        walkEdges(
          start: "'"$perm_id"'",
          edgeTypes: ["ActsOn"],
          direction: "OUTGOING",
          depth: 10
        ) {
          id
          label
        }
      }
    ')
    FOUND=$(echo "$HOP2_RESPONSE" | jq -r '[.data.walkEdges[]? | select(.label == "Secret")][0].id // empty')
    if [[ -n "$FOUND" ]]; then
        SECRET_ID="$FOUND"
        break
    fi
done

# Capture the CMK-encrypted secret id for the follow-up walks.
# The specific-ARN grant targets org-master-api-key, so the Secret on this
# path is the CMK-encrypted one (ARN carries a random suffix; resolve at runtime).
if [[ -n "$SECRET_ID" ]]; then
    log_pass "Secret reachable via Principal->Permission->ActsOn path: $SECRET_ID"
    assert_contains "$SECRET_ID" "org-master-api-key" "path Secret is the specific-ARN grant target"
else
    log_fail "No Secret reachable via Permission ActsOn edges; downstream secret walks cannot run"
    summary
fi

# ============================================================================
# Test 2: Secret -EncryptedBy-> KmsKey (customer CMK)
# ============================================================================
echo ""
echo "Test 2: Secret EncryptedBy edge (customer CMK)"

ENC_RESPONSE=$(gql '
  query {
    walkEdges(
      start: "'"$SECRET_ID"'",
      edgeTypes: ["EncryptedBy"],
      direction: "OUTGOING",
      depth: 1
    ) {
      id
      label
    }
  }
')

KMS_COUNT=$(echo "$ENC_RESPONSE" | jq '[.data.walkEdges[]? | select(.label == "KmsKey")] | length')
assert_gt "$KMS_COUNT" "0" "Secret -EncryptedBy-> KmsKey edge exists"

# ============================================================================
# Test 3: Secret -AllowsAccessFrom-> external cross-account Principal
# ============================================================================
echo ""
echo "Test 3: Secret AllowsAccessFrom edge (cross-account resource policy)"

ACCESS_RESPONSE=$(gql '
  query {
    walkEdges(
      start: "'"$SECRET_ID"'",
      edgeTypes: ["AllowsAccessFrom"],
      direction: "OUTGOING",
      depth: 1
    ) {
      id
      label
    }
  }
')

ACCESS_COUNT=$(echo "$ACCESS_RESPONSE" | jq '.data.walkEdges | length')
assert_gt "$ACCESS_COUNT" "0" "Secret has AllowsAccessFrom edge(s) from its resource policy"

EXTERNAL_HIT=$(echo "$ACCESS_RESPONSE" | jq -r '[.data.walkEdges[]? | select(.id == "'"$EXTERNAL_ROOT_ARN"'")] | length')
assert_gt "$EXTERNAL_HIT" "0" "external cross-account principal ($EXTERNAL_ROOT_ARN) materialized"

# ============================================================================
# Test 4: Lambda function Resource node + AllowsAccessFrom edges
# ============================================================================
echo ""
echo "Test 4: Lambda resource-policy AllowsAccessFrom edges"

FN_RESPONSE=$(gql '
  query {
    findNode(label: "Resource", id: "'"$LAMBDA_FUNCTION_ARN"'") {
      id
      label
    }
  }
')
FN_TYPE=$(echo "$FN_RESPONSE" | jq -r '.data.findNode | type')
assert_eq "$FN_TYPE" "object" "Lambda function exists as a Resource node"

LAMBDA_ACCESS_RESPONSE=$(gql '
  query {
    walkEdges(
      start: "'"$LAMBDA_FUNCTION_ARN"'",
      edgeTypes: ["AllowsAccessFrom"],
      direction: "OUTGOING",
      depth: 1
    ) {
      id
      label
    }
  }
')

LAMBDA_ACCESS_COUNT=$(echo "$LAMBDA_ACCESS_RESPONSE" | jq '.data.walkEdges | length')
assert_gt "$LAMBDA_ACCESS_COUNT" "0" "Lambda function has AllowsAccessFrom edge(s) from its resource policy"

echo ""
summary
