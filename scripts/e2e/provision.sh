#!/bin/bash

################################################################################
# provision.sh
#
# Provision the activable deployment for E2E testing:
# 1. Prereq check: Envoy Gateway exists in envoy-gateway-system namespace
# 2. Build the activable-server image from the current branch (or skip with --skip-build)
# 3. Verify the image is loaded into Docker Desktop (docker image inspect)
# 4. Helm upgrade/install activable chart with route.enabled=true
# 5. Wait for HTTPRoute to be Accepted/ResolvedRefs
# 6. Verify GraphQL endpoint is ready (introspection query returns 200)
#
# Usage:
#   ./provision.sh                # build + deploy + wait
#   ./provision.sh --skip-build    # skip build, use existing image
#
# Requires:
#   - kubectl, helm, curl, jq
#   - Docker with Docker Desktop k8s context
#   - activable-server image tag matching IMAGE_TAG (from config.sh)
#
################################################################################

set -euo pipefail

# Source config and lib
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"
source "$SCRIPT_DIR/lib.sh"

# Parse arguments
SKIP_BUILD="${1:---skip-build}"  # default: skip build
if [[ "$SKIP_BUILD" != "--skip-build" ]]; then
    SKIP_BUILD="false"
else
    SKIP_BUILD="true"
fi

# ============================================================================
# Main Flow
# ============================================================================

echo "=== E2E Provision: Build + Deploy + Wait ==="
echo "GRAPHQL_URL: $GRAPHQL_URL"
echo "NS: $NS"
echo "IMAGE_TAG: $IMAGE_TAG"
echo "SKIP_BUILD: $SKIP_BUILD"
echo ""

# Step 1: Preflight (check kubectl, helm, curl, jq, Gateway)
echo "Step 1: Preflight checks..."
if ! preflight "true"; then
    echo "ERROR: Preflight failed. Cannot proceed."
    exit 1
fi
echo ""

# Step 2: Prereq — Envoy Gateway must exist
echo "Step 2: Checking Envoy Gateway prereq..."
if ! kubectl -n envoy-gateway-system get gateway activable-gateway &> /dev/null; then
    cat >&2 <<'EOF'
ERROR: Envoy Gateway 'activable-gateway' not found in envoy-gateway-system namespace.

The shared Gateway must be deployed before provisioning activable.
See: deploy/gateway/README.md

To install:
  cd deploy/gateway/
  ./gen-local-cert.sh
  ./install-envoy-gateway.sh

Then re-run: ./provision.sh
EOF
    exit 1
fi
echo "✓ Envoy Gateway 'activable-gateway' found in envoy-gateway-system"
echo ""

# Step 3: Build image (if not --skip-build)
if [[ "$SKIP_BUILD" == "false" ]]; then
    echo "Step 3: Building activable-server image..."
    echo "Running: make build-linux (or equivalent docker build)"

    # Use the project's build command
    # Assumes Makefile has a 'build-linux' or 'docker-build' target
    # The image should be tagged as activable-server:$IMAGE_TAG
    if ! make -C "$(git rev-parse --show-toplevel)" build-linux; then
        echo "ERROR: Build failed. Check Makefile and try again."
        exit 1
    fi
    echo "✓ Image built: activable-server:$IMAGE_TAG"
else
    echo "Step 3: Skipping build (--skip-build)"
fi
echo ""

# Step 4: Verify image is loaded into Docker Desktop
echo "Step 4: Verifying image is loaded..."
if ! docker image inspect "activable-server:$IMAGE_TAG" &> /dev/null; then
    cat >&2 <<EOF
ERROR: Image not found: activable-server:$IMAGE_TAG

The helm chart uses imagePullPolicy: Never, which requires the image
to be present in Docker Desktop's local image store.

Check:
  docker image ls | grep activable-server
  docker image inspect activable-server:$IMAGE_TAG

If the image exists but docker fails, verify Docker Desktop is running
and the kubectl context is docker-desktop.

If the image doesn't exist, run:
  ./provision.sh  # without --skip-build

Then re-run: ./provision.sh --skip-build
EOF
    exit 1
fi
echo "✓ Image verified: activable-server:$IMAGE_TAG"
echo ""

# Step 5: Helm upgrade/install
echo "Step 5: Helm upgrade/install activable chart..."
echo "Command: helm upgrade --install activable deploy/helm/activable"
echo "         -f deploy/helm/activable/values-local.yaml"
echo "         --set database.password=activable_dev"
echo "         --set route.enabled=true"
echo "         --set image.tag=$IMAGE_TAG"
echo "         -n $NS --create-namespace --wait --timeout 300s"
echo ""

# The chart requires database.password (pulled from the secret)
# route.enabled=true ensures the HTTPRoute is rendered
# imagePullPolicy: Never (set in values.yaml)
if ! helm upgrade --install activable deploy/helm/activable \
    -f deploy/helm/activable/values-local.yaml \
    --set "database.password=activable_dev" \
    --set "route.enabled=true" \
    --set "image.tag=$IMAGE_TAG" \
    -n "$NS" \
    --create-namespace \
    --wait \
    --timeout 300s; then
    echo "ERROR: Helm upgrade/install failed."
    echo "Check: helm status activable -n $NS"
    echo "Logs: kubectl logs -n $NS -l app=activable --tail=50"
    exit 1
fi
echo "✓ Helm upgrade/install succeeded"
echo ""

# Step 6: Verify HTTPRoute is Accepted/ResolvedRefs
echo "Step 6: Verifying HTTPRoute status..."
if ! wait_for "kubectl -n $NS get httproute activable-route -o jsonpath='{.status.parents[0].conditions[?(@.type==\"Accepted\")].status}' 2>/dev/null | grep -qi true" 120; then
    echo "WARN: HTTPRoute did not reach Accepted=True within 120s"
    echo "Checking status..."
    kubectl -n "$NS" describe httproute activable-route || true
fi
echo "✓ HTTPRoute Accepted=True"
echo ""

# Step 7: Verify GraphQL endpoint is ready
echo "Step 7: Verifying GraphQL endpoint..."
if ! wait_for "gql '{ __schema { queryType { name } } }' | jq -e '.data.__schema.queryType.name == \"QueryRoot\"' >/dev/null" 120; then
    echo "ERROR: GraphQL endpoint did not respond correctly within 120s"
    echo "Checking: $GRAPHQL_URL"
    echo "Response:"
    gql '{ __schema { queryType { name } } }' | jq . || true
    exit 1
fi
echo "✓ GraphQL endpoint ready (schema queryType = QueryRoot)"
echo ""

echo "=== Provision Complete ==="
echo "Activable is deployed and ready at: $GRAPHQL_URL"
echo ""
echo "Next: run ./seed.sh to seed the database with adversarial scenarios"
