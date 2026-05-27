#!/bin/bash

################################################################################
# config.sh
#
# Configuration for the E2E harness: endpoints, credentials, account IDs,
# namespaces, image tags, database connection info, seed job manifest path.
#
# All values are sourced by lib.sh, provision.sh, seed.sh, reset.sh, and
# scenario scripts.
#
# Environment overrides:
#   GRAPHQL_URL=https://... ./run-all.sh
#   GRAPH=staging NS=staging-e2e IMAGE_TAG=qa ./run-all.sh
#
################################################################################

set -u

# ============================================================================
# GraphQL Gateway URL (HTTP/HTTPS over the shared Gateway)
# ============================================================================
# No port-forward; relies on mkcert-trusted TLS (activable.localtest.me).
GRAPHQL_URL="${GRAPHQL_URL:-https://activable.localtest.me/graphql}"

# ============================================================================
# Database and Graph Configuration
# ============================================================================
# The AGE graph name to seed/reset (must match schema).
GRAPH="${GRAPH:-cloud}"

# Kubernetes namespace where the activable deployment lives.
NS="${NS:-default}"

# ============================================================================
# Docker Image Configuration
# ============================================================================
# Image tag for the built activable-server image (e.g. "dev", "latest", "qa").
# Matches the value passed to helm --set image.tag=...
IMAGE_TAG="${IMAGE_TAG:-dev}"

# ============================================================================
# AWS Account IDs (Adversarial Seed Scenarios)
# ============================================================================
# 4-account model: dev, staging, prod, secrets (LocalStack multi-account routing).
# Used by seed.sh to run the in-cluster adversarial seed Job.
ACCOUNT_DEV="111111111111"
ACCOUNT_STAGING="222222222222"
ACCOUNT_PROD="333333333333"
ACCOUNT_SECRETS="444444444444"

# ============================================================================
# Seed Job Configuration
# ============================================================================
# Path to the seed Job manifest (ConfigMap + Job).
# MUST be renamed from floci-seed-job.yaml to seed-adversarial-job.yaml.
SEED_JOB_MANIFEST="${SEED_JOB_MANIFEST:-deploy/k8s/seed-adversarial-job.yaml}"

# ============================================================================
# PostgreSQL Pod and Database Configuration
# ============================================================================
# Pod name selector for postgres in the cluster (e.g. activable-postgres-0).
PG_POD="${PG_POD:-activable-postgres-0}"

# Postgres username for admin commands (reset, schema queries).
PG_USER="${PG_USER:-postgres}"

# Postgres database name.
PG_DB="${PG_DB:-activable}"

# ============================================================================
# Isolation Gate for reset.sh (HARD GATE)
# ============================================================================
# reset.sh requires explicit opt-in to prevent accidental drops of shared state.
# Default: unset (refuse to run unless explicitly allowed + running on local context).
E2E_ALLOW_RESET="${E2E_ALLOW_RESET:-}"

# ============================================================================
# Input Validation
# ============================================================================

validate_identifier() {
    local name="$1"
    local value="$2"
    local pattern="^[a-z0-9_-]+$"

    if ! [[ "$value" =~ $pattern ]]; then
        cat >&2 <<EOF
ERROR: $name='$value' contains invalid characters.
       Must match regex: $pattern (lowercase alphanumeric, underscore, hyphen only).
       Example: GRAPH=cloud, NS=default
EOF
        return 1
    fi
}

# Validate GRAPH (used in kubectl exec psql commands)
if ! validate_identifier "GRAPH" "$GRAPH"; then
    exit 1
fi

# Validate NS (used in kubectl exec commands)
if ! validate_identifier "NS" "$NS"; then
    exit 1
fi

# Export for use in all sourcing scripts
export GRAPHQL_URL GRAPH NS IMAGE_TAG
export ACCOUNT_DEV ACCOUNT_STAGING ACCOUNT_PROD ACCOUNT_SECRETS
export SEED_JOB_MANIFEST
export PG_POD PG_USER PG_DB
export E2E_ALLOW_RESET
