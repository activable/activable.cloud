.PHONY: setup lint test test-integration bindgen build ingest smoke verify verify-rust verify-go test-ffi-stability size-check spike-bench clean dev-up dev-down dev-reset dev-seed dev-ingest dev-query dev-status dev-logs

# Platform detection for Rust dylib
UNAME_S := $(shell uname -s)
RUST_DYLIB_EXT := $(if $(filter Darwin,$(UNAME_S)),.dylib,.so)
RUST_DYLIB := target/release/libactivable_ffi$(RUST_DYLIB_EXT)

# Diagnostic output
$(info Detected platform: $(UNAME_S))
$(info Rust dylib extension: $(RUST_DYLIB_EXT))
$(info Rust dylib path: $(RUST_DYLIB))

setup:
	@echo "Setting up development environment..."
	@rustup show
	@go version
	@command -v pre-commit >/dev/null 2>&1 || { echo "pre-commit not found; install with 'pip install pre-commit' or 'brew install pre-commit'"; exit 1; }
	@pre-commit install --install-hooks
	@echo "Setup complete"

lint:
	@echo "Linting Rust code..."
	cargo fmt --check --all
	cargo clippy --workspace --all-targets -- -D warnings
	@echo "Linting Go code..."
	gofmt -l ./go
	golangci-lint run ./go/...
	@echo "Lint complete"

test:
	@echo "Testing Rust code..."
	cargo test --workspace
	@echo "Testing Go code..."
	go test -race -v ./go/...

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
	export DYLD_LIBRARY_PATH=$(PWD)/target/release; \
	export LD_LIBRARY_PATH=$(PWD)/target/release; \
	set -e; \
	echo "Running Rust integration tests..."; \
	cargo test --test '*_integration*' --release -- --nocapture 2>&1; \
	echo "Running Go integration tests..."; \
	go test -v -tags integration ./tests/integration/go/... 2>&1
	@echo "Step 5: Teardown"
	docker compose -f infra/compose/docker-compose.yml down -v
	@echo "✓ Integration tests completed"

bindgen:
	@echo "Regenerating UniFFI bindings..."
	@cargo build --manifest-path crates/activable-ffi/Cargo.toml --release
	@echo "Generating Go bindings from $(RUST_DYLIB)..."
	@mkdir -p bindings/activable_ffi
	@if ! command -v uniffi-bindgen-go >/dev/null 2>&1; then \
		echo "uniffi-bindgen-go not found. Install with: cargo install --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.7.1+v0.31.0 uniffi-bindgen-go"; \
		exit 1; \
	fi
	uniffi-bindgen-go --library $(RUST_DYLIB) --out-dir bindings/
	@echo "OK: bindings regenerated"

build:
	@echo "Building Rust workspace..."
	cargo build --workspace --release
	@echo "Building Go CLI with CGO..."
	@mkdir -p go/bin
	CGO_ENABLED=1 CGO_LDFLAGS="-L$(PWD)/target/release -lactivable_ffi" go build -o go/bin/activable ./go/cmd/activable
	@echo "Build complete (CGO enabled; requires libactivable_ffi.dylib at runtime)"

ingest:
	@echo "Error: ingest not yet implemented"
	@exit 1

verify: verify-rust verify-go
	@echo "verify: all checks passed"

verify-rust:
	@echo "Verifying Rust (fmt + clippy + test + build)..."
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace
	cargo build --workspace --release

verify-go:
	@echo "Verifying Go (lint + test)..."
	cd go && golangci-lint run --timeout=2m ./...
	DYLD_LIBRARY_PATH=$(PWD)/target/release LD_LIBRARY_PATH=$(PWD)/target/release CGO_LDFLAGS="-L$(PWD)/target/release" \
	  go test -race ./go/...

smoke:
	@echo "Running smoke test..."
	@if [ ! -f go/bin/activable ]; then echo "Binary not found; run 'make build' first"; exit 1; fi
	DYLD_LIBRARY_PATH=$(PWD)/target/release LD_LIBRARY_PATH=$(PWD)/target/release go/bin/activable verify
	@echo "Smoke test passed"

test-ffi-stability:
	@echo "Running FFI stability test (concurrent goroutines)..."
	@if [ ! -f target/release/libactivable_ffi$(RUST_DYLIB_EXT) ]; then echo "Rust library not found; run 'make build' first"; exit 1; fi
	bash scripts/test-ffi-stability.sh

size-check:
	@echo "Checking binary size..."
	@bash scripts/size-check.sh go/bin/activable

spike-bench:
	@echo "Starting Postgres+AGE (idempotent)..."
	docker compose -f infra/compose/docker-compose.yml up -d db
	@echo "Waiting for Postgres healthcheck..."
	@for i in 1 2 3 4 5; do \
		if docker compose -f infra/compose/docker-compose.yml ps db | grep -q healthy; then \
			echo "Postgres ready"; \
			break; \
		fi; \
		echo "Waiting... ($$i/5)"; \
		sleep 3; \
	done
	@echo "Running graph backend spike: generate + load + benchmark + verdict"
	cargo run --release --manifest-path spike/graph-backend/Cargo.toml -- \
		bench-all \
		--output /tmp/spike-graphs \
		--db-host localhost \
		--db-port 5433 \
		--db-user activable \
		--db-password activable_dev \
		--seed 42
	@exit_code=$$?; \
	if [ $$exit_code -eq 0 ]; then \
		echo "✓ Verdict: GO — PG+AGE approved"; \
	elif [ $$exit_code -eq 1 ]; then \
		echo "✗ Verdict: NO-GO — Escalate for user decision"; \
	elif [ $$exit_code -eq 2 ]; then \
		echo "⚠  Verdict: BORDERLINE — User arbitrates"; \
	fi; \
	exit $$exit_code

clean:
	cargo clean
	rm -rf go/bin target/
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
	@echo "Seeding Floci with test AWS resources via Go SDK..."
	@FLOCI_POD=$$(kubectl get pod -l app.kubernetes.io/component=aws-emulator -o jsonpath='{.items[0].metadata.name}' 2>/dev/null); \
	if [ -z "$$FLOCI_POD" ]; then echo "✗ Floci pod not found. Run 'make dev-up' first."; exit 1; fi
	kubectl port-forward svc/activable-floci 4566:4566 &
	@sleep 2
	AWS_ENDPOINT_URL=http://localhost:4566 \
	AWS_ACCESS_KEY_ID=test \
	AWS_SECRET_ACCESS_KEY=test \
	AWS_DEFAULT_REGION=us-east-1 \
	  go run ./go/cmd/seed
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

dev-logs:
	@echo "Tailing Docker Compose logs (Ctrl-C to stop)..."
	docker compose -f $(COMPOSE_DEV) logs -f
