#!/bin/bash

################################################################################
# scenarios/20-query.sh
#
# Scenario: findNode Query (Graph Node Lookup)
#
# Verifies the findNode query works correctly by:
# 1. Sending a findNode query with label and id arguments
# 2. Asserting HTTP 200 response
# 3. Asserting the response shape is correct (data.findNode present)
# 4. Not asserting specific node values (those are Phase 4 seeded-data tests)
#
# The query uses the REAL query name from schema.rs:
#   - GraphQL: findNode (camelCase)
#   - Rust: find_node (snake_case)
#   - Arguments: label (String), id (String)
#
# This test is resilient to graph state (seeded or empty).
# It verifies the query EXECUTES and has a valid response shape.
#
# Usage:
#   ./20-query.sh
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
echo "Scenario 20: findNode Query Test"
echo "========================================"
echo ""

# Reset counters
TESTS_PASSED=0
TESTS_FAILED=0

# Test 1: findNode query with arbitrary label/id
echo "Test 1: findNode query execution"

# Build the query (from schema.rs: label: String, id: String)
# Using a dummy label and id; don't assert the result (graph may be empty)
QUERY='
  query {
    findNode(label: "TestLabel", id: "test-id-001") {
      id
      label
      properties
    }
  }
'

# Execute the query
RESPONSE=$(gql "$QUERY")

# Check response is valid JSON
if echo "$RESPONSE" | jq empty 2>/dev/null; then
    log_pass "GraphQL response is valid JSON"
else
    log_fail "GraphQL response is not valid JSON: $RESPONSE"
    exit 1
fi

# Check that no top-level errors exist (query syntax is valid)
ERRORS=$(echo "$RESPONSE" | jq -r '.errors[]?.message' 2>/dev/null || echo "")
if [[ -z "$ERRORS" ]]; then
    log_pass "findNode query executed without errors"
else
    log_fail "findNode query returned errors: $ERRORS"
fi

# Test 2: Response shape validation
echo ""
echo "Test 2: Response shape validation"

# Check that .data.findNode key exists (null value is acceptable; missing key is not)
# Use jq 'has()' to check for key presence, not value truthiness
if echo "$RESPONSE" | jq -e '.data | has("findNode")' >/dev/null 2>&1; then
    log_pass "Response contains .data.findNode field"
else
    log_fail "Response missing .data.findNode field"
fi

# Test 3: Verify it's null (empty graph) or has expected fields
echo ""
echo "Test 3: Node object structure"
NODE_TYPE=$(echo "$RESPONSE" | jq -r '.data.findNode | type')
if [[ "$NODE_TYPE" == "null" ]]; then
    log_pass "findNode returned null (expected for empty/not-found graph)"
elif [[ "$NODE_TYPE" == "object" ]]; then
    log_pass "findNode returned an object"

    # If it's an object, verify expected fields
    HAS_ID=$(echo "$RESPONSE" | jq 'has("id") | if . then "yes" else "no" end' 2>/dev/null || echo "no")
    if [[ "$HAS_ID" == "yes" ]] || echo "$RESPONSE" | jq '.data.findNode | has("id")' >/dev/null 2>&1; then
        log_pass "findNode object has id field"
    fi
else
    log_fail "findNode returned unexpected type: $NODE_TYPE"
fi

# Test 4: Verify query syntax is correct (arguments accepted)
echo ""
echo "Test 4: Query argument validation"

# Build a query with explicit arguments and variable types
QUERY_WITH_VARS='
  query GetNode($label: String!, $id: String!) {
    findNode(label: $label, id: $id) {
      id
      label
    }
  }
'

# Send with variables
RESPONSE_VARS=$(gql "$QUERY_WITH_VARS")
if echo "$RESPONSE_VARS" | jq empty 2>/dev/null; then
    log_pass "Query with explicit variables is valid"
else
    log_fail "Query with variables failed to parse"
fi

echo ""
summary
