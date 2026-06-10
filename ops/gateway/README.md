# Envoy Gateway + Local TLS Deployment

This directory contains the standalone Envoy Gateway deployment for the Activable platform. The gateway is **separate from the activable application chart** and provides a shared ingress layer for routing external traffic to internal services.

## Overview

- **Controller:** Envoy Gateway (via Helm chart)
- **API:** Kubernetes Gateway API v1 (not legacy nginx Ingress)
- **TLS:** Locally-trusted mkcert certificate for `activable.localtest.me` (development only)
- **Namespace:** `envoy-gateway-system` (isolates gateway infrastructure)
- **Hostname:** `activable.localtest.me` → resolves to 127.0.0.1 (via public `localtest.me` DNS)

Services attach to the shared Gateway via `HTTPRoute` resources (e.g., `activable-httproute` in the `activable` namespace).

## Prerequisites

### Host Requirements

1. **mkcert** — Locally-trusted TLS certificate tool
   ```bash
   # macOS
   brew install mkcert

   # Linux (Fedora/RHEL)
   sudo dnf install mkcert

   # Linux (Debian/Ubuntu)
   sudo apt install mkcert

   # Windows: download from https://github.com/FiloSottile/mkcert/releases
   ```

2. **mkcert CA installed locally** (one-time setup)
   ```bash
   mkcert -install
   ```
   - **macOS:** Adds the CA to Keychain.
   - **Linux:** Adds the CA to the system trust store via `update-ca-certificates`.
   - **Windows:** Adds the CA to the Trusted Root Certification Authorities store.

3. **Docker-Desktop Kubernetes** enabled and running

4. **kubectl** and **helm** configured to access the cluster

5. **curl** and **jq** for verification scripts (optional)

### DNS

The hostname `activable.localtest.me` resolves to `127.0.0.1` via the public `localtest.me` DNS service.
No local `/etc/hosts` entry needed, but you may add one for redundancy:
```
127.0.0.1  activable.localtest.me
```

## Installation

### Step 1: Generate TLS Certificate (Host-side)

Run the certificate generation script on your host (NOT in the cluster):

```bash
./gen-local-cert.sh
```

This:
- Generates a locally-trusted certificate for `activable.localtest.me` using mkcert.
- Creates/updates the Kubernetes TLS secret `activable-tls` in the `envoy-gateway-system` namespace.
- Is idempotent — safe to run multiple times.

**Output:**
- `/tmp/activable.localtest.me.crt` (cert file)
- `/tmp/activable.localtest.me.key` (key file)
- Kubernetes secret `activable-tls` in `envoy-gateway-system`

### Step 2: Install Envoy Gateway

Deploy the Envoy Gateway controller and the shared Gateway:

```bash
./install-envoy-gateway.sh
```

This:
- Installs the Envoy Gateway Helm chart in `envoy-gateway-system`.
- Waits for the controller Deployment to be ready.
- Applies `gatewayclass.yaml` and `gateway.yaml`.
- **Verifies the LoadBalancer Service address is reachable** (critical gate).
- Confirms the Gateway `Programmed=True` condition.

**Expected output:**
```
=== Envoy Gateway Installation ===
Preflight: OK (kubectl, helm, curl, mkcert, cluster, DNS)
Installing Envoy Gateway v1.2.0 in namespace envoy-gateway-system...
Envoy Gateway helm chart installed.
Waiting for Envoy Gateway controller Deployment to be ready (max 180s)...
Envoy Gateway controller is ready.
Applying GatewayClass and Gateway...
Manifests applied.
Verifying Gateway LoadBalancer Service address...
LoadBalancer address found: ...
Gateway activable-gateway is Programmed=True. LoadBalancer verification passed.
=== Envoy Gateway Installation Complete ===
```

## Verification

### TLS Connectivity

Once the Gateway is installed, verify TLS termination and routing:

```bash
curl -sf https://activable.localtest.me/
```

**Expected behavior:**
- TLS connection succeeds without `--insecure` flag (mkcert CA is trusted).
- Response: `404` or `503` from Envoy Gateway (no backend routes yet — this is expected and proves TLS+routing work).
- No certificate warnings in the browser.

### Gateway Status

Check the Gateway resource and LoadBalancer Service:

```bash
# Gateway Programmed condition
kubectl -n envoy-gateway-system get gateway activable-gateway

# LoadBalancer Service
kubectl -n envoy-gateway-system get svc -l gateway.envoyproxy.io/owning-gateway-name=activable-gateway

# Envoy Gateway controller Deployment
kubectl -n envoy-gateway-system get deploy envoy-gateway
```

### TLS Secret

Verify the certificate is loaded:

```bash
kubectl -n envoy-gateway-system get secret activable-tls -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -text -noout
```

## Attaching Services

To attach a service to the Gateway, create an `HTTPRoute` resource in your service's namespace and label the namespace.

### Step 1: Label the Namespace

The `activable` namespace (or any namespace hosting HTTPRoutes) MUST be labeled with `gateway.activable.io/expose=true` to allow its HTTPRoute resources to attach to the shared Gateway:

```bash
kubectl label namespace activable gateway.activable.io/expose=true
```

This label is matched by the Gateway's `allowedRoutes.namespaces.from: Selector` and is the mechanism that scopes route attachment.

### Step 2: Create the HTTPRoute

Create an `HTTPRoute` resource in your service's namespace:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: my-service-route
  namespace: activable  # Labeled with gateway.activable.io/expose=true
spec:
  parentRefs:
    - name: activable-gateway
      namespace: envoy-gateway-system  # Cross-namespace reference
  rules:
    - backendRefs:
        - name: my-service
          port: 8080
```

**Key points:**
- The namespace MUST be labeled `gateway.activable.io/expose=true` — this is the only requirement for HTTPRoute→Gateway attachment.
- The `parentRef` points to the shared `activable-gateway` in `envoy-gateway-system`.
- The Gateway's `allowedRoutes.namespaces.from: Selector` (in `gateway.yaml`) enforces this namespace label requirement.

## Troubleshooting

### Certificate Errors

**Problem:** `curl: (60) SSL certificate problem`

**Solution:**
1. Verify mkcert CA is installed: `mkcert -CAROOT`
2. Regenerate the certificate: `./gen-local-cert.sh --force-renew`
3. Verify the secret exists: `kubectl -n envoy-gateway-system get secret activable-tls`

### LoadBalancer Address Pending

**Problem:** `kubectl get svc` shows `<pending>` for the LoadBalancer address.

**Solution (Docker-Desktop):**
- Docker-Desktop's LoadBalancer controller is optional. If not configured:
  1. Enable Kubernetes in Docker-Desktop settings.
  2. Restart Docker.
  3. Re-run `./install-envoy-gateway.sh`.
- As a fallback, use port-forwarding (not recommended for normal use):
  ```bash
  kubectl -n envoy-gateway-system port-forward svc/envoy-gateway 8080:80 8443:443 &
  curl -k https://localhost:8443/  # Use -k flag without trusted cert
  ```

### DNS Resolution

**Problem:** `activable.localtest.me` does not resolve.

**Solution:**
1. Test DNS: `nslookup activable.localtest.me 1.1.1.1`
2. Verify localtest.me is reachable: `curl -I http://activable.localtest.me`
3. Add a local `/etc/hosts` entry as a fallback:
   ```
   127.0.0.1  activable.localtest.me
   ```

### Gateway Not Programmed

**Problem:** Gateway status shows `Programmed=False`.

**Solution:**
1. Check Gateway description: `kubectl -n envoy-gateway-system describe gateway activable-gateway`
2. Verify the GatewayClass is accepted: `kubectl -n envoy-gateway-system get gatewayclass activable-eg`
3. Check Envoy Gateway controller logs: `kubectl -n envoy-gateway-system logs -l app.kubernetes.io/name=gateway`

## Maintenance

### Certificate Renewal

mkcert certificates are valid for 397 days. To renew before expiry:

```bash
./gen-local-cert.sh --force-renew
```

The Envoy Gateway will pick up the updated secret automatically (no restart needed).

### Updating Envoy Gateway

To update the Envoy Gateway chart version:

1. Edit `install-envoy-gateway.sh` and update the `EG_VERSION` variable:
   ```bash
   EG_VERSION="v1.3.0"  # or later
   ```

2. Verify the new version is available:
   ```bash
   helm search repo envoyproxy/gateway-helm --version '<new-version>'
   ```

3. Re-run the install script:
   ```bash
   ./install-envoy-gateway.sh
   ```

## CA Cleanup (Local Development Only)

**Important:** mkcert's CA is local-development only. When finished with local development, clean up the installed CA:

### macOS
```bash
# View all certificates in Keychain
security find-certificate -a | grep -i mkcert

# Remove the mkcert CA from Keychain
# Open Keychain Access → search for "mkcert" → delete each entry
# OR use the command-line:
mkcert -uninstall  # Newer mkcert versions (2.4.0+)
```

**Manual cleanup (if uninstall not available):**
```bash
# macOS: remove from Keychain using security tool
security find-certificate -a -c "mkcert" | while IFS= read -r line; do
  if [[ "$line" =~ cert=\"([^\"]+)\" ]]; then
    security delete-certificate -Z "${BASH_REMATCH[1]}" 2>/dev/null || true
  fi
done
```

### Linux (Debian/Ubuntu)
```bash
# Locate mkcert CA files (usually in ~/.local/share/mkcert/)
ls ~/.local/share/mkcert/

# Remove the CA from the system trust store
sudo rm /usr/local/share/ca-certificates/mkcert.crt
sudo update-ca-certificates

# Remove mkcert files
rm -rf ~/.local/share/mkcert/
```

### Linux (Fedora/RHEL)
```bash
# Remove mkcert CA
sudo rm /etc/pki/ca-trust/source/anchors/mkcert.crt
sudo update-ca-trust

# Remove mkcert files
rm -rf ~/.local/share/mkcert/
```

### Windows
```powershell
# Open Certmgr (Certificate Manager)
certmgr.msc

# Navigate to: Trusted Root Certification Authorities → Certificates
# Find and delete the mkcert CA entry

# Or via PowerShell:
Get-ChildItem -Path Cert:\CurrentUser\Root | Where-Object { $_.Subject -like "*mkcert*" } | Remove-Item
```

## Production Deployment

For production, **do NOT use mkcert**. Instead:

1. Use a real certificate from Let's Encrypt via cert-manager.
2. Apply the `letsencrypt-clusterissuer.example.yaml` (customize email + domain).
3. Update the Gateway listener to reference a cert-manager-managed secret.
4. cert-manager will automatically provision and renew certificates.

See `letsencrypt-clusterissuer.example.yaml` for the issuer configuration.

## Architecture

```
┌─────────────────────────────────────┐
│      Docker-Desktop Localhost       │
│         127.0.0.1 :80 / :443        │
└──────────────┬──────────────────────┘
               │
    activable.localtest.me
               │
         ┌─────▼─────┐
         │LoadBalancer│ (K8s Service)
         │   Service  │
         └─────┬──────┘
               │
      ┌────────▼────────┐
      │  Envoy Gateway  │ (envoy-gateway-system namespace)
      │  Pod/Deployment │
      └────────┬────────┘
               │
         ┌─────▼──────────┐
         │ Shared Gateway │ (HTTP/HTTPS listeners)
         │ activable-gw   │ (TLS: activable-tls secret)
         └─────┬──────────┘
               │
        ┌──────┴──────────────────┐
        │                         │
  ┌─────▼─────┐         ┌────────▼────────┐
  │HTTPRoute  │         │HTTPRoute         │
  │(app1)     │         │(app2)            │
  │namespace:1│         │namespace:2       │
  └──────┬────┘         └────────┬─────────┘
         │                      │
    ┌────▼──┐            ┌──────▼────┐
    │Service │            │Service    │
    │app1:80 │            │app2:80    │
    └────────┘            └───────────┘
```

## Related Files

- `install-envoy-gateway.sh` — Helm install + preflight + LoadBalancer verification (F2 critical gate).
- `gen-local-cert.sh` — mkcert cert generation + TLS secret creation.
- `gatewayclass.yaml` — Envoy Gateway GatewayClass definition.
- `gateway.yaml` — Shared Gateway with HTTP/HTTPS listeners and namespace label selector.
- `letsencrypt-clusterissuer.example.yaml` — Production cert-manager issuer (inactive locally).

## See Also

- [Kubernetes Gateway API](https://gateway-api.sigs.k8s.io/)
- [Envoy Gateway Documentation](https://gateway.envoyproxy.io/)
- [mkcert GitHub](https://github.com/FiloSottile/mkcert)
- [cert-manager Documentation](https://cert-manager.io/)
