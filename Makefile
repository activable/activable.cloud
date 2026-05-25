.PHONY: setup lint test test-integration build build-linux deploy-dev probe-accounts ingest verify clean dev-up dev-down dev-reset dev-seed dev-ingest dev-query dev-status dev-logs

# Cross-compile activable-graphql for linux/arm64 (K8s pod target on M-series Mac).
# Bakes the toolchain + zig PATH so we never re-diagnose homebrew rust shadowing rustup.
# Uses sccache if available for incremental rebuild speedups (~10x after cold compile).
RUSTUP_BIN := $(HOME)/.rustup/toolchains/1.95-aarch64-apple-darwin/bin
ZIG_BIN    := /opt/homebrew/opt/zig@0.14/bin
BUILD_PATH := $(RUSTUP_BIN):$(HOME)/.cargo/bin:$(ZIG_BIN):$(PATH)
SCCACHE    := $(shell command -v sccache 2>/dev/null)

RTK := $(shell command -v rtk 2>/dev/null)

build-linux:
	@echo "Building activable-graphql for aarch64-unknown-linux-gnu via zigbuild..."
	@if [ -n "$(SCCACHE)" ]; then echo "sccache active: $(SCCACHE)"; fi
	@if [ -z "$(RTK)" ]; then echo "warning: rtk not on PATH; build output will be unfiltered"; fi
	PATH="$(BUILD_PATH)" RUSTC_WRAPPER="$(SCCACHE)" \
		$(RTK) cargo zigbuild --target aarch64-unknown-linux-gnu --profile release-fast -p activable-graphql
	@echo "✓ Linux binary ready: target/aarch64-unknown-linux-gnu/release-fast/activable-graphql"

deploy-dev: build-linux
	$(RTK) docker build -f deploy/docker/Dockerfile -t activable-server:dev .
	$(RTK) kubectl rollout restart deployment/activable
	$(RTK) kubectl rollout status deployment/activable --timeout=240s
	@echo "✓ Deployed and rolled out"

# Live-verify gate per CLAUDE.md §1.5 — query cascadeRiskScore for the four seeded accounts.
# Usage: make probe-accounts GRAPHQL_URL=http://localhost:8080/graphql
GRAPHQL_URL ?= http://localhost:8080/graphql
probe-accounts:
	@for acct in 111111111111 222222222222 333333333333 444444444444; do \
		echo "=== account $$acct ==="; \
		$(RTK) curl -sS -X POST -H "Content-Type: application/json" \
			-d "{\"query\":\"{ accountRisks(accountId: \\\"$$acct\\\") { cascadeRiskScore cascadeSeverity allSignals { cfEscalation { score severity matchedRuleIds } } } }\"}" \
			"$(GRAPHQL_URL)" | jq .; \
	done

setup:
	@echo "Setting up development environment..."
	@rustup show
	@command -v pre-commit >/dev/null 2>&1 || { echo "pre-commit not found; install with 'pip install pre-commit' or 'brew install pre-commit'"; exit 1; }
	@pre-commit install --install-hooks
	@echo "Setup complete"

lint:
	@echo "Linting Rust code..."
	cargo fmt --check --all
	cargo clippy --workspace --all-targets -- -D warnings
	@echo "Lint complete"

test:
	@echo "Testing Rust code..."
	cargo test --workspace

test-integration: build
	@echo "Integration tests: teardown → deploy → wait-healthy → test → teardown"
	@echo "Step 1: Teardown (clean slate)"
	docker compose -f infra/compose/docker-compose.yml down -v || true
	@echo "Step 2: Deploy Postgres+AGE"
	docker compose -f infra/compose/docker-compose.yml up -d db
	@echo "Step 3: Wait for healthy status (timeout 30s)"
	@timeout=30; \
	while [ $$timeout -gt 0 ]; do \
		if docker compose -f infra/compose/docker-compose.yml ps db | grep -q healthy; then \
			echo "✓ Postgres ready"; \
			break; \
		fi; \
		echo "  Waiting... ($$(expr 30 - $$timeout)s)"; \
		sleep 2; \
		timeout=$$(expr $$timeout - 2); \
	done; \
	if [ $$timeout -le 0 ]; then \
		echo "✗ Postgres failed to become healthy"; \
		docker compose -f infra/compose/docker-compose.yml down -v; \
		exit 1; \
	fi
	@echo "Step 4: Run integration tests"
	@export AGE_TEST_URL="postgres://activable:activable_dev@localhost:5433/activable?sslmode=disable"; \
	export ACTIVABLE_DB_URL="postgres://activable:activable_dev@localhost:5433/activable?sslmode=disable"; \
	export ACTIVABLE_INTEGRATION=1; \
	set -e; \
	echo "Running Rust integration tests..."; \
	cargo test --test '*_integration*' --release -- --nocapture 2>&1
	@echo "Step 5: Teardown"
	docker compose -f infra/compose/docker-compose.yml down -v
	@echo "✓ Integration tests completed"

build:
	@echo "Building Rust workspace..."
	cargo build --workspace --release
	@echo "Build complete"

ingest:
	@echo "Error: ingest not yet implemented"
	@exit 1

verify:
	@echo "Verifying Rust (fmt + clippy + test + build)..."
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace
	cargo build --workspace --release
	@echo "verify: all checks passed"

clean:
	cargo clean
	find . -name "*.o" -delete
	@echo "Clean complete"

# ===== Local Development Environment (Pure Kubernetes — Docker Desktop K8s) =====
# ALL services (Postgres+AGE, Floci, Activable GraphQL) run as K8s resources.
# Zero Docker Compose. Ingestion triggered via GraphQL mutation, not CLI.

.PHONY: dev-up dev-down dev-reset dev-seed dev-ingest dev-query dev-status dev-logs

dev-up:
	@echo "=== Deploying to Docker Desktop Kubernetes ==="
	@kubectl cluster-info > /dev/null 2>&1 || { echo "✗ Kubernetes not available. Enable: Docker Desktop > Settings > Kubernetes > Enable"; exit 1; }
	@echo ""
	@echo "Step 1: Building Docker image..."
	docker build -t activable-server:dev -f deploy/docker/Dockerfile .
	@echo "✓ Docker image built"
	@echo ""
	@echo "Step 2: Deploying Helm chart (Postgres+AGE + Floci + GraphQL server)..."
	helm upgrade --install activable deploy/helm/activable \
		-f deploy/helm/activable/values-local.yaml \
		--wait --timeout 300s
	@echo "✓ Helm deployment successful"
	@echo ""
	@echo "Step 3: Waiting for all pods ready..."
	kubectl wait --for=condition=ready pod -l app.kubernetes.io/instance=activable --timeout=120s 2>/dev/null || true
	@echo ""
	@echo "=== Local Dev Environment Ready (Pure K8s) ==="
	@echo ""
	@echo "  GraphQL API:      http://localhost:30080/graphql"
	@echo "  GraphQL Playground: http://localhost:30080/"
	@echo "  Healthcheck:      http://localhost:30080/healthz"
	@echo ""
	@echo "Next steps:"
	@echo "  make dev-seed      # Seed Floci with test AWS resources"
	@echo "  make dev-ingest    # Trigger ingestion via GraphQL mutation"
	@echo "  make dev-query     # Query the graph via GraphQL"

dev-down:
	@echo "Stopping K8s deployment (preserves PVCs)..."
	helm uninstall activable 2>/dev/null || echo "Nothing to uninstall"
	@echo "✓ Stopped. PVCs preserved for next dev-up."

dev-reset:
	@echo "Resetting all K8s resources + destroying data..."
	helm uninstall activable 2>/dev/null || true
	kubectl delete pvc -l app.kubernetes.io/instance=activable 2>/dev/null || true
	@echo "✓ Reset complete. Run 'make dev-up' for a fresh environment."

dev-seed:
	@echo "Seeding Floci with test AWS resources..."
	@FLOCI_POD=$$(kubectl get pod -l app.kubernetes.io/component=aws-emulator -o jsonpath='{.items[0].metadata.name}' 2>/dev/null); \
	if [ -z "$$FLOCI_POD" ]; then echo "✗ Floci pod not found. Run 'make dev-up' first."; exit 1; fi
	kubectl port-forward svc/activable-floci 4566:4566 &
	@sleep 2
	AWS_ENDPOINT_URL=http://localhost:4566 \
	AWS_ACCESS_KEY_ID=test \
	AWS_SECRET_ACCESS_KEY=test \
	AWS_DEFAULT_REGION=us-east-1 \
	  bash infra/scripts/seed-floci.sh
	@kill %1 2>/dev/null || true
	@echo "✓ Seed complete"

dev-ingest:
	@echo "Triggering ingestion via GraphQL mutation..."
	@curl -sf http://localhost:30080/healthz > /dev/null 2>&1 || { echo "✗ GraphQL API not ready at localhost:30080. Run 'make dev-up' first."; exit 1; }
	@echo ""
	curl -s -X POST http://localhost:30080/graphql \
		-H "Content-Type: application/json" \
		-d '{"query":"mutation { triggerIngest(provider: \"aws\", regions: [\"us-east-1\"]) { id status startedAt } }"}' | \
	if command -v jq > /dev/null 2>&1; then jq .; else cat; fi
	@echo ""
	@echo "Ingestion triggered. Check status with:"
	@echo "  make dev-query"

dev-query:
	@echo "Querying graph via GraphQL..."
	@curl -sf http://localhost:30080/healthz > /dev/null 2>&1 || { echo "✗ GraphQL API not ready."; exit 1; }
	@echo ""
	@echo "--- findNode (alice) ---"
	@curl -s -X POST http://localhost:30080/graphql \
		-H "Content-Type: application/json" \
		-d '{"query":"{ findNode(label: \"Principal\", id: \"arn:aws:iam::000000000000:user/alice\") { id label properties } }"}' | \
	if command -v jq > /dev/null 2>&1; then jq .; else cat; fi
	@echo ""
	@echo "--- walkEdges (from alice) ---"
	@curl -s -X POST http://localhost:30080/graphql \
		-H "Content-Type: application/json" \
		-d '{"query":"{ walkEdges(startId: \"arn:aws:iam::000000000000:user/alice\", edgeTypes: [\"HasPermission\",\"MemberOf\"], direction: \"OUTGOING\", depth: 2) { id label } }"}' | \
	if command -v jq > /dev/null 2>&1; then jq .; else cat; fi

dev-status:
	@echo "=== Kubernetes Pods ==="
	@kubectl get pods -l app.kubernetes.io/instance=activable -o wide 2>/dev/null || echo "No pods found"
	@echo ""
	@echo "=== Kubernetes Services ==="
	@kubectl get svc -l app.kubernetes.io/instance=activable 2>/dev/null || echo "No services found"
	@echo ""
	@echo "=== Service Health ==="
	@curl -sf http://localhost:30080/healthz > /dev/null 2>&1 && echo "✓ GraphQL API: http://localhost:30080" || echo "✗ GraphQL API: not responding"

dev-logs:
	@echo "Streaming logs from Activable server pod..."
	kubectl logs -f -l app.kubernetes.io/name=activable --tail=50
