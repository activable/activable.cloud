#!/bin/bash

################################################################################
# seed.sh
#
# Apply the adversarial seed Job to populate LocalStack with test scenarios.
#
# Single-source reconciliation:
# - The standalone source is deploy/scripts/seed-adversarial.sh (one truth)
# - At apply time, generate a ConfigMap FROM the standalone file
# - The Job manifest (deploy/k8s/seed-adversarial-job.yaml) mounts the ConfigMap
# - No embedded script copy (avoids drift)
#
# Usage:
#   ./seed.sh
#
# The script:
# 1. Creates a ConfigMap from deploy/scripts/seed-adversarial.sh
# 2. Applies the Job manifest (seed-adversarial-job.yaml)
# 3. Waits for Job to complete (max 300s)
#
# Returns: 0 if Job completed successfully, 1 if timeout or error
#
################################################################################

set -euo pipefail

# Source config and lib
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"
source "$SCRIPT_DIR/lib.sh"

echo "=== E2E Seed: Apply Adversarial Scenarios ==="
echo ""

# Step 1: Preflight
echo "Step 1: Preflight checks..."
if ! preflight "false"; then
    echo "ERROR: Preflight failed. Cannot proceed."
    exit 1
fi
echo ""

# Step 2: Generate ConfigMap from standalone seed script
echo "Step 2: Creating ConfigMap from standalone seed script..."
echo "Source: deploy/scripts/seed-adversarial.sh"

if [[ ! -f "deploy/scripts/seed-adversarial.sh" ]]; then
    echo "ERROR: deploy/scripts/seed-adversarial.sh not found."
    echo "Must run from the project root: cd /path/to/activable.cloud"
    exit 1
fi

# Create ConfigMap from the file (--from-file)
# Name: localstack-seed-adversarial-script (matches Job's volumeMount)
# Namespace: same as deployment (typically 'default')
# Dry-run to generate YAML, then apply
kubectl create configmap localstack-seed-adversarial-script \
    --from-file=seed-adversarial.sh=deploy/scripts/seed-adversarial.sh \
    --dry-run=client \
    -o yaml \
    -n "$NS" | kubectl apply -f -

echo "✓ ConfigMap created/updated: localstack-seed-adversarial-script"
echo ""

# Step 3: Apply Job manifest
echo "Step 3: Applying seed Job manifest..."
echo "Manifest: $SEED_JOB_MANIFEST"

if [[ ! -f "$SEED_JOB_MANIFEST" ]]; then
    echo "ERROR: Seed Job manifest not found: $SEED_JOB_MANIFEST"
    echo "Expected: deploy/k8s/seed-adversarial-job.yaml"
    exit 1
fi

# Apply the Job (will be created or re-run if deleted/completed)
kubectl apply -f "$SEED_JOB_MANIFEST" -n "$NS"
echo "✓ Job manifest applied"
echo ""

# Step 4: Wait for Job to complete
echo "Step 4: Waiting for Job to complete (max 300s)..."
JOB_NAME="localstack-seed-adversarial"

if ! wait_for "kubectl -n $NS get job $JOB_NAME -o jsonpath='{.status.succeeded}' 2>/dev/null | grep -qE '^[1-9]'" 300; then
    echo "ERROR: Job did not complete within 300s."
    echo "Job status:"
    kubectl -n "$NS" describe job "$JOB_NAME" || true
    echo ""
    echo "Job logs:"
    kubectl -n "$NS" logs -l job-name="$JOB_NAME" --all-containers=true --tail=100 || true
    exit 1
fi

echo "✓ Job completed successfully"
echo ""

# Step 5: Verify job output (optional; log a sample)
echo "Step 5: Job output (last 20 lines):"
kubectl -n "$NS" logs -l job-name="$JOB_NAME" --all-containers=true --tail=20 || true
echo ""

echo "=== Seed Complete ==="
echo "Adversarial scenarios are seeded in LocalStack."
echo "Next: run ./reset.sh to reset the graph, then ./scenarios/00-health.sh to verify"
