#!/bin/bash

################################################################################
# gen-local-cert.sh
#
# Generate a locally-trusted TLS certificate for activable.localtest.me using mkcert
# and create/update the Kubernetes TLS secret in envoy-gateway-system.
#
# Prerequisites:
# - mkcert is installed (install via: brew install mkcert)
# - mkcert CA is installed locally (run once: mkcert -install)
# - kubectl is configured and can access the cluster
#
# Usage:
#   ./gen-local-cert.sh [--force-renew]
#
# Flags:
#   --force-renew    Delete and recreate the cert and k8s secret (default: idempotent)
#
# Output:
#   - /tmp/activable.localtest.me.crt  (cert file)
#   - /tmp/activable.localtest.me.key  (key file)
#   - k8s TLS secret: activable-tls in envoy-gateway-system namespace
#
################################################################################

set -euo pipefail

HOSTNAME="activable.localtest.me"
CERT_FILE="/tmp/${HOSTNAME}.crt"
KEY_FILE="/tmp/${HOSTNAME}.key"
NAMESPACE="envoy-gateway-system"
SECRET_NAME="activable-tls"

FORCE_RENEW=false
if [[ $# -gt 0 ]] && [[ "$1" == "--force-renew" ]]; then
    FORCE_RENEW=true
fi

# === Preflight checks ===
preflight_check() {
    if ! command -v mkcert &> /dev/null; then
        echo "ERROR: mkcert not installed. Install via: brew install mkcert" >&2
        exit 1
    fi

    if ! mkcert -CAROOT &> /dev/null; then
        echo "ERROR: mkcert CA not installed. Run: mkcert -install" >&2
        exit 1
    fi

    if ! command -v kubectl &> /dev/null; then
        echo "ERROR: kubectl not installed." >&2
        exit 1
    fi

    echo "Preflight: OK (mkcert, mkcert CA, kubectl)"
}

# === Generate certificate ===
generate_cert() {
    if [[ $FORCE_RENEW == true ]] && [[ -f "${CERT_FILE}" ]]; then
        echo "Removing old certificate files (--force-renew)..."
        rm -f "${CERT_FILE}" "${KEY_FILE}"
    fi

    if [[ -f "${CERT_FILE}" ]] && [[ -f "${KEY_FILE}" ]]; then
        echo "Certificate already exists at ${CERT_FILE}. Skipping generation (use --force-renew to regenerate)."
        return
    fi

    echo "Generating mkcert certificate for ${HOSTNAME}..."
    mkcert -cert-file "${CERT_FILE}" -key-file "${KEY_FILE}" "${HOSTNAME}"
    echo "Certificate generated at ${CERT_FILE}"
}

# === Create/update Kubernetes TLS secret ===
create_k8s_secret() {
    echo "Creating/updating Kubernetes TLS secret ${SECRET_NAME} in namespace ${NAMESPACE}..."

    # Use kubectl create secret with --dry-run=client to generate the secret manifest,
    # then apply it (idempotent via kubectl apply).
    kubectl create secret tls "${SECRET_NAME}" \
        --cert="${CERT_FILE}" \
        --key="${KEY_FILE}" \
        -n "${NAMESPACE}" \
        --dry-run=client \
        -o yaml | kubectl apply -f -

    echo "TLS secret ${SECRET_NAME} created/updated in namespace ${NAMESPACE}."
}

# === Main ===
main() {
    echo "=== Generate Local TLS Certificate ==="
    preflight_check
    generate_cert
    create_k8s_secret
    echo "=== TLS Certificate Ready ==="
    echo ""
    echo "Next: run install-envoy-gateway.sh to deploy the Gateway."
}

main "$@"
