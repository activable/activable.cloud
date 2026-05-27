#!/bin/bash

################################################################################
# lib.sh
#
# Shared library functions for the E2E harness:
# - gql() — POST a GraphQL query to $GRAPHQL_URL via curl over HTTPS (mkcert)
# - assert_* — equality, contains, greater-than, JSON path assertions
# - wait_for() — poll a command until success or timeout
# - log_pass/log_fail — colored output with counters
# - summary() — print total pass/fail counts
# - preflight() — fail fast if dependencies missing (kubectl, curl, jq, helm, mkcert, Gateway reachable)
#
# All functions assume config.sh has already been sourced.
#
################################################################################

set -euo pipefail

# ============================================================================
# Global Counters
# ============================================================================
TESTS_PASSED=0
TESTS_FAILED=0

# ============================================================================
# gql() — POST a GraphQL query to $GRAPHQL_URL
# ============================================================================
# Usage:
#   response=$(gql '{ __schema { queryType { name } } }')
#   # or
#   gql 'query findNode($label: String!, $id: String!) {
#     findNode(label: $label, id: $id) { id label }
#   }'
#
# Returns: raw JSON response body
# Exits on curl/HTTP error (non-2xx status)
#
gql() {
    local query="$1"

    # Wrap the query in a GraphQL POST body
    local body
    body=$(jq -n --arg q "$query" '{"query": $q}')

    # POST to GRAPHQL_URL via curl
    # -sS: silent but show errors
    # -X POST: HTTP method
    # -H "Content-Type: application/json": JSON request
    # --data: POST body
    # mkcert is already trusted locally; NO --insecure or -k flag
    curl -sS \
        -X POST \
        -H "Content-Type: application/json" \
        --data "$body" \
        "$GRAPHQL_URL"
}

# ============================================================================
# gql_extract() — POST query and extract a jq path from the response
# ============================================================================
# Usage:
#   findNode=$(gql_extract '{ findNode(label: "User", id: "u1") { id } }' '.data.findNode')
#
gql_extract() {
    local query="$1"
    local jq_path="$2"

    gql "$query" | jq -r "$jq_path"
}

# ============================================================================
# assert_eq() — Assert two strings are equal
# ============================================================================
# Usage:
#   assert_eq "actual" "expected" "description"
#
assert_eq() {
    local actual="$1"
    local expected="$2"
    local desc="${3:-assertion}"

    if [[ "$actual" == "$expected" ]]; then
        log_pass "$desc: '$actual' == '$expected'"
    else
        log_fail "$desc: expected '$expected', got '$actual'"
    fi
}

# ============================================================================
# assert_contains() — Assert string contains a substring
# ============================================================================
# Usage:
#   assert_contains "$haystack" "needle" "description"
#
assert_contains() {
    local haystack="$1"
    local needle="$2"
    local desc="${3:-assertion}"

    if [[ "$haystack" == *"$needle"* ]]; then
        log_pass "$desc: contains '$needle'"
    else
        log_fail "$desc: expected to contain '$needle', got: $haystack"
    fi
}

# ============================================================================
# assert_gt() — Assert first number is greater than second
# ============================================================================
# Usage:
#   assert_gt "10" "5" "count should be > 5"
#
assert_gt() {
    local actual="$1"
    local threshold="$2"
    local desc="${3:-assertion}"

    if (( actual > threshold )); then
        log_pass "$desc: $actual > $threshold"
    else
        log_fail "$desc: expected > $threshold, got $actual"
    fi
}

# ============================================================================
# assert_json_eq() — Assert JSON value at jq path matches expected
# ============================================================================
# Usage:
#   response=$(gql '{ __schema { queryType { name } } }')
#   assert_json_eq "$response" '.data.__schema.queryType.name' 'QueryRoot' 'schema check'
#
assert_json_eq() {
    local json="$1"
    local jq_path="$2"
    local expected="$3"
    local desc="${4:-assertion}"

    local actual
    actual=$(echo "$json" | jq -r "$jq_path" 2>/dev/null || echo "ERROR")

    if [[ "$actual" == "$expected" ]]; then
        log_pass "$desc: $jq_path == '$expected'"
    else
        log_fail "$desc: expected $jq_path='$expected', got '$actual'"
    fi
}

# ============================================================================
# wait_for() — Poll a command until success or timeout
# ============================================================================
# Usage:
#   wait_for 'curl -sf https://activable.localtest.me/graphql' 60
#   wait_for 'kubectl get pod my-pod -o jsonpath={.status.phase} | grep -q Running' 120
#
# Returns: 0 if command succeeds within timeout, 1 if timeout exceeded
#
wait_for() {
    local cmd="$1"
    local timeout_s="${2:-60}"
    local elapsed=0

    while (( elapsed < timeout_s )); do
        if eval "$cmd" >/dev/null 2>&1; then
            return 0
        fi
        elapsed=$((elapsed + 1))
        sleep 1
    done

    return 1
}

# ============================================================================
# log_pass() — Log a passing test (green)
# ============================================================================
log_pass() {
    local msg="$1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    printf "\033[32m✓ PASS\033[0m %s\n" "$msg"
}

# ============================================================================
# log_fail() — Log a failing test (red)
# ============================================================================
log_fail() {
    local msg="$1"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    printf "\033[31m✗ FAIL\033[0m %s\n" "$msg"
}

# ============================================================================
# summary() — Print total pass/fail counts
# ============================================================================
summary() {
    echo ""
    echo "========================================"
    printf "Tests PASSED: \033[32m%d\033[0m\n" "$TESTS_PASSED"
    printf "Tests FAILED: \033[31m%d\033[0m\n" "$TESTS_FAILED"
    echo "========================================"

    if (( TESTS_FAILED > 0 )); then
        return 1
    fi
    return 0
}

# ============================================================================
# preflight() — Fail fast if dependencies missing or Gateway unreachable
# ============================================================================
# Checks:
# - kubectl is installed and cluster is accessible
# - curl is installed
# - jq is installed
# - (optional) helm is installed (needed for provision.sh)
# - (optional) mkcert is installed (needed for TLS cert generation)
# - GraphQL URL is reachable (POST a simple introspection query)
#
# Returns: 0 if all checks pass, 1 if any check fails
#
preflight() {
    local check_helm="${1:-false}"  # set to true if provision.sh is running
    local errors=()

    echo "=== Preflight Checks ==="

    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        errors+=("kubectl not found. Install: https://kubernetes.io/docs/tasks/tools/")
    else
        # Verify cluster is accessible
        if ! kubectl cluster-info &> /dev/null; then
            errors+=("kubectl: cluster not accessible. Check current context: kubectl config current-context")
        fi
    fi

    # Check curl
    if ! command -v curl &> /dev/null; then
        errors+=("curl not found. Install: https://curl.se/download.html")
    fi

    # Check jq
    if ! command -v jq &> /dev/null; then
        errors+=("jq not found. Install: https://stedolan.github.io/jq/download/")
    fi

    # Check helm (if provision.sh)
    if [[ "$check_helm" == "true" ]]; then
        if ! command -v helm &> /dev/null; then
            errors+=("helm not found. Install: https://helm.sh/docs/intro/install/")
        fi
    fi

    # Check mkcert (optional; only warn)
    if ! command -v mkcert &> /dev/null; then
        echo "WARN: mkcert not found. TLS certs may not be generated. Install: https://github.com/FiloSottile/mkcert"
    fi

    # Verify Gateway is reachable (GraphQL POST)
    echo "Checking GraphQL endpoint: $GRAPHQL_URL"
    if ! gql '{ __schema { queryType { name } } }' > /dev/null 2>&1; then
        errors+=("GraphQL endpoint not reachable: $GRAPHQL_URL")
        errors+=("  - Is the Gateway deployed? Check: kubectl -n envoy-gateway-system get gateway activable-gateway")
        errors+=("  - Is activable deployed? Check: kubectl -n $NS get deploy")
        errors+=("  - Is mkcert CA trusted? Check: mkcert -CAROOT")
        errors+=("  - Does activable.localtest.me resolve? Check: nslookup activable.localtest.me 1.1.1.1")
    fi

    # Report errors
    if (( ${#errors[@]} > 0 )); then
        echo "ERRORS:"
        for err in "${errors[@]}"; do
            echo "  $err"
        done
        return 1
    fi

    echo "✓ All preflight checks passed"
    return 0
}

# Export functions and counters
export -f gql gql_extract
export -f assert_eq assert_contains assert_gt assert_json_eq
export -f wait_for
export -f log_pass log_fail summary
export -f preflight
export TESTS_PASSED TESTS_FAILED
