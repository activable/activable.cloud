#!/bin/bash

################################################################################
# scenarios/00-health.sh
#
# Scenario: GraphQL Schema Introspection (Health Check)
#
# Verifies the GraphQL server is healthy by:
# 1. Sending a schema introspection query
# 2. Asserting HTTP 200 response
# 3. Asserting the response contains the QueryRoot type
#
# This is a minimal health check that doesn't require seeded data.
# It verifies the Gateway and GraphQL server are both operational.
#
# Usage:
#   ./00-health.sh
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
echo "Scenario 00: GraphQL Health Check"
echo "========================================"
echo ""

# Reset counters
TESTS_PASSED=0
TESTS_FAILED=0

# Test 1: Schema introspection query
echo "Test 1: Schema introspection (queryType name)"
RESPONSE=$(gql '{ __schema { queryType { name } } }')

# Check response is valid JSON
if echo "$RESPONSE" | jq empty 2>/dev/null; then
    log_pass "GraphQL response is valid JSON"
else
    log_fail "GraphQL response is not valid JSON: $RESPONSE"
    exit 1
fi

# Check that no top-level errors exist
if echo "$RESPONSE" | jq -e '.errors | length == 0' >/dev/null 2>&1; then
    log_pass "GraphQL response has no top-level errors"
else
    ERRORS=$(echo "$RESPONSE" | jq '.errors // []')
    log_fail "GraphQL response contains errors: $ERRORS"
fi

# Check queryType name is QueryRoot
assert_json_eq "$RESPONSE" '.data.__schema.queryType.name' 'QueryRoot' \
    "Schema queryType name"

# Test 2: Verify other query types exist (higher-order check)
echo ""
echo "Test 2: Query types enumeration"
QUERY_NAMES=$(echo "$RESPONSE" | jq -r '.data.__schema.types[].name' | head -5)
if [[ -n "$QUERY_NAMES" ]]; then
    log_pass "GraphQL schema contains types"
else
    log_fail "GraphQL schema has no types"
fi

echo ""
summary
