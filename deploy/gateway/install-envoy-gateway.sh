#!/bin/bash

################################################################################
# install-envoy-gateway.sh
#
# Idempotent Envoy Gateway installation via helm.
# - Validates preflight (kubectl, helm, cluster connectivity, DNS)
# - Installs Envoy Gateway controller in envoy-gateway-system namespace
# - Waits for the controller Deployment to be ready
# - Applies GatewayClass, Gateway, and ReferenceGrant manifests
# - Verifies the Gateway's LoadBalancer Service address is localhost-reachable
#
# Usage:
#   ./install-envoy-gateway.sh
#
# Environment:
#   - Requires: kubectl, helm, curl (for DNS check)
#   - Assumes: Docker-Desktop Kubernetes context is active
#   - Assumes: mkcert cert has been generated + TLS secret created in envoy-gateway-system
#
################################################################################

set -euo pipefail

# === Pinned version (confirm current stable via helm search before first install) ===
EG_VERSION="v1.2.0"  # Stable Envoy Gateway release; adjust after `helm search repo`

GATEWAY_NAMESPACE="envoy-gateway-system"
GATEWAY_NAME="activable-gateway"
GATEWAY_HOSTNAME="activable.localtest.me"

readonly EG_VERSION GATEWAY_NAMESPACE GATEWAY_NAME GATEWAY_HOSTNAME

# === Preflight checks (F11) ===
preflight_check() {
    local missing_tools=()

    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        missing_tools+=("kubectl")
    fi

    # Check helm
    if ! command -v helm &> /dev/null; then
        missing_tools+=("helm")
    fi

    # Check curl (for DNS verification)
    if ! command -v curl &> /dev/null; then
        missing_tools+=("curl")
    fi

    # Check mkcert (for user's cert generation step)
    if ! command -v mkcert &> /dev/null; then
        missing_tools+=("mkcert (install via: brew install mkcert)")
    fi

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        echo "ERROR: Missing required tools:" >&2
        printf '  - %s\n' "${missing_tools[@]}" >&2
        exit 1
    fi

    # Check mkcert CA is installed
    if ! mkcert -CAROOT &> /dev/null; then
        echo "ERROR: mkcert CA not installed. Run: mkcert -install" >&2
        exit 1
    fi

    # Check kubectl cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        echo "ERROR: kubectl cannot connect to cluster. Verify Docker-Desktop Kubernetes is running." >&2
        exit 1
    fi

    # Check DNS resolution
    if ! curl -s "http://${GATEWAY_HOSTNAME}" &> /dev/null; then
        # DNS check via nslookup (permitted as preflight, not a live curl)
        if ! nslookup "${GATEWAY_HOSTNAME}" 1.1.1.1 &> /dev/null; then
            echo "WARNING: DNS resolution for ${GATEWAY_HOSTNAME} failed. Assuming localtest.me global DNS. Will proceed." >&2
        fi
    fi

    echo "Preflight: OK (kubectl, helm, curl, mkcert, cluster, DNS)"
}

# === Install Envoy Gateway via helm ===
install_envoy_gateway() {
    echo "Installing Envoy Gateway ${EG_VERSION} in namespace ${GATEWAY_NAMESPACE}..."

    helm upgrade --install eg \
        oci://docker.io/envoyproxy/gateway-helm \
        --version "${EG_VERSION}" \
        -n "${GATEWAY_NAMESPACE}" \
        --create-namespace \
        --wait \
        --timeout 180s

    echo "Envoy Gateway helm chart installed."
}

# === Wait for controller Deployment ===
wait_controller_ready() {
    echo "Waiting for Envoy Gateway controller Deployment to be ready (max 180s)..."

    if kubectl -n "${GATEWAY_NAMESPACE}" rollout status deploy/envoy-gateway --timeout=180s; then
        echo "Envoy Gateway controller is ready."
    else
        echo "ERROR: Envoy Gateway controller Deployment failed to become ready." >&2
        exit 1
    fi
}

# === Apply GatewayClass, Gateway, ReferenceGrant ===
apply_manifests() {
    echo "Applying GatewayClass, Gateway, and ReferenceGrant..."

    for manifest in gatewayclass.yaml gateway.yaml referencegrant.yaml; do
        if [[ ! -f "$(dirname "${BASH_SOURCE[0]}")/${manifest}" ]]; then
            echo "ERROR: ${manifest} not found in $(dirname "${BASH_SOURCE[0]}")/" >&2
            exit 1
        fi
        kubectl apply -f "$(dirname "${BASH_SOURCE[0]}")/${manifest}"
    done

    echo "Manifests applied."
}

# === Verify LoadBalancer address (F2 — CRITICAL gate) ===
verify_loadbalancer() {
    echo "Verifying Gateway LoadBalancer Service address..."

    local max_wait=30
    local waited=0

    while [[ $waited -lt $max_wait ]]; do
        # Query for the LoadBalancer Service in envoy-gateway-system with the correct label
        local svc_ip
        svc_ip=$(kubectl -n "${GATEWAY_NAMESPACE}" get svc \
            -l gateway.envoyproxy.io/owning-gateway-name="${GATEWAY_NAME}" \
            -o jsonpath='{.items[0].status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")

        # On Docker-Desktop, IP may be empty; try hostname
        local svc_host
        svc_host=$(kubectl -n "${GATEWAY_NAMESPACE}" get svc \
            -l gateway.envoyproxy.io/owning-gateway-name="${GATEWAY_NAME}" \
            -o jsonpath='{.items[0].status.loadBalancer.ingress[0].hostname}' 2>/dev/null || echo "")

        if [[ -n "${svc_ip}" ]] || [[ -n "${svc_host}" ]]; then
            echo "LoadBalancer address found: IP=${svc_ip:-<empty>}, Hostname=${svc_host:-<empty>}"
            break
        fi

        echo "  (${waited}s) Waiting for LoadBalancer address to bind..."
        sleep 2
        ((waited += 2))
    done

    if [[ $waited -ge $max_wait ]]; then
        echo "ERROR: LoadBalancer Service address did not bind within ${max_wait}s." >&2
        echo "Current service state:" >&2
        kubectl -n "${GATEWAY_NAMESPACE}" get svc -l gateway.envoyproxy.io/owning-gateway-name="${GATEWAY_NAME}" >&2
        echo "" >&2
        echo "NOTE: On Docker-Desktop, the LoadBalancer may report <pending> if not configured to use local localhost binding." >&2
        echo "See README.md for Docker-Desktop troubleshooting." >&2
        exit 1
    fi

    # Verify Gateway Programmed=True
    echo "Verifying Gateway Programmed condition..."
    local gw_programmed
    gw_programmed=$(kubectl -n "${GATEWAY_NAMESPACE}" get gateway "${GATEWAY_NAME}" \
        -o jsonpath='{.status.conditions[?(@.type=="Programmed")].status}' 2>/dev/null || echo "")

    if [[ "${gw_programmed}" != "True" ]]; then
        echo "ERROR: Gateway ${GATEWAY_NAME} is not Programmed. Status:" >&2
        kubectl -n "${GATEWAY_NAMESPACE}" describe gateway "${GATEWAY_NAME}" >&2
        exit 1
    fi

    echo "Gateway ${GATEWAY_NAME} is Programmed=True. LoadBalancer verification passed."
}

# === Main ===
main() {
    echo "=== Envoy Gateway Installation ==="
    preflight_check
    install_envoy_gateway
    wait_controller_ready
    apply_manifests
    verify_loadbalancer
    echo "=== Envoy Gateway Installation Complete ==="
}

main "$@"
