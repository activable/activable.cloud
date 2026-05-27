#!/bin/bash

################################################################################
# reset.sh
#
# Reset the database for a clean E2E run:
# 1. Drop and recreate the AGE graph (default: 'cloud')
# 2. Truncate the scheduler jobs table (deterministic state)
#
# ISOLATION GATE (CRITICAL):
# This script modifies shared cluster state (the 'cloud' graph + jobs table).
# Requires explicit opt-in:
#   - E2E_ALLOW_RESET=1 environment variable
#   - kubectl context must be a known-local context (docker-desktop, minikube, etc.)
#
# Usage:
#   E2E_ALLOW_RESET=1 ./reset.sh              # allow reset (local context)
#   E2E_ALLOW_RESET=1 ./reset.sh              # will still fail if context is production
#
# Requires:
#   - kubectl, psql (or kubectl exec)
#   - Valid GRAPH, NS, PG_POD, PG_USER, PG_DB from config.sh
#
################################################################################

set -euo pipefail

# Source config and lib
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"
source "$SCRIPT_DIR/lib.sh"

echo "=== E2E Reset: Drop Graph + Truncate Jobs ==="
echo ""

# Step 1: Isolation Gate
echo "Step 1: Checking isolation gate..."
if [[ -z "$E2E_ALLOW_RESET" ]]; then
    cat >&2 <<'EOF'
ERROR: E2E_ALLOW_RESET is not set.

reset.sh drops the shared 'cloud' graph and truncates the jobs table.
This is destructive and may affect live traffic if run against a
production or shared cluster.

To allow reset on a local context, run:
  E2E_ALLOW_RESET=1 ./reset.sh

The script will still refuse to run if the kubectl context appears
to be a remote/production cluster.
EOF
    exit 1
fi

# Check kubectl context (fail if it looks like production)
CURRENT_CONTEXT=$(kubectl config current-context)
echo "Current kubectl context: $CURRENT_CONTEXT"

case "$CURRENT_CONTEXT" in
    docker-desktop|minikube|kind-*|localhost*|127.0.0.1*|local*|dev-*)
        echo "✓ Context appears to be local (allowed)"
        ;;
    *)
        cat >&2 <<EOF
ERROR: kubectl context '$CURRENT_CONTEXT' does not appear to be local.

This may be a production or shared cluster. reset.sh is disabled for safety.

If you are certain this is a safe, local cluster, re-run with:
  E2E_ALLOW_RESET=1 ./reset.sh  # (already set) and add to context check if needed

Recognized local contexts: docker-desktop, minikube, kind-*, localhost*, dev-*
EOF
        exit 1
        ;;
esac
echo ""

# Step 2: Preflight
echo "Step 2: Preflight checks..."
if ! preflight "false"; then
    echo "ERROR: Preflight failed. Cannot proceed."
    exit 1
fi
echo ""

# Step 3: Validate GRAPH and NS (already validated in config.sh, but re-check here)
echo "Step 3: Validating parameters..."
echo "GRAPH: $GRAPH"
echo "NS: $NS"
echo "PG_POD: $PG_POD"

if [[ -z "$GRAPH" || -z "$NS" ]]; then
    echo "ERROR: GRAPH or NS not set. Check config.sh"
    exit 1
fi
echo "✓ Parameters valid"
echo ""

# Step 4: Verify postgres pod exists
echo "Step 4: Checking postgres pod..."
if ! kubectl -n "$NS" get pod "$PG_POD" &> /dev/null; then
    echo "ERROR: Postgres pod not found: $PG_POD in namespace $NS"
    echo "Check: kubectl -n $NS get pods | grep postgres"
    exit 1
fi
echo "✓ Postgres pod found: $PG_POD"
echo ""

# Step 5: Drop and recreate graph
echo "Step 5: Dropping and recreating AGE graph '$GRAPH'..."
kubectl -n "$NS" exec -i "$PG_POD" -- \
    psql -U "$PG_USER" -d "$PG_DB" \
    -c "SELECT * FROM ag_catalog.drop_graph('$GRAPH', true);" || true

echo "Creating fresh graph '$GRAPH'..."
kubectl -n "$NS" exec -i "$PG_POD" -- \
    psql -U "$PG_USER" -d "$PG_DB" \
    -c "SELECT * FROM ag_catalog.create_graph('$GRAPH');"

echo "✓ Graph dropped and recreated: $GRAPH"
echo ""

# Step 6: Truncate jobs table
echo "Step 6: Truncating scheduler jobs table..."
kubectl -n "$NS" exec -i "$PG_POD" -- \
    psql -U "$PG_USER" -d "$PG_DB" \
    -c "TRUNCATE TABLE jobs;"

echo "✓ Jobs table truncated"
echo ""

echo "=== Reset Complete ==="
echo "Graph '$GRAPH' and jobs table are clean."
echo "Next: run ./seed.sh to re-populate scenarios, or run scenarios directly"
