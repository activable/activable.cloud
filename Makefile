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

# ===== Local Development Environment (Docker Compose + Docker Desktop K8s) =====

COMPOSE_DEV := infra/compose/docker-compose.dev.yml

dev-up:
	@echo "Starting local dev environment (Docker Compose infra + Docker Desktop K8s app)..."
	@echo ""
	@echo "Step 1: Starting infrastructure (Postgres+AGE + Floci)..."
	docker compose -f $(COMPOSE_DEV) up -d
	@echo "Step 2: Waiting for services to be healthy (timeout 60s)..."
	@timeout=60; \
	while [ $$timeout -gt 0 ]; do \
		healthy_count=0; \
		if docker compose -f $(COMPOSE_DEV) ps db 2>/dev/null | grep -q "healthy"; then healthy_count=$$(($$healthy_count + 1)); fi; \
		if docker compose -f $(COMPOSE_DEV) ps floci 2>/dev/null | grep -q "healthy"; then healthy_count=$$(($$healthy_count + 1)); fi; \
		if [ $$healthy_count -ge 2 ]; then \
			echo "✓ All services healthy"; \
			break; \
		fi; \
		echo "  Waiting... ($$(expr 60 - $$timeout)s)"; \
		sleep 3; \
		timeout=$$(expr $$timeout - 3); \
	done
	@if [ $$timeout -le 0 ]; then echo "✗ Services failed to become healthy"; exit 1; fi
	@echo ""
	@echo "Step 3: Building Docker image for K8s..."
	docker build -t activable/activable-server:latest -f deploy/docker/Dockerfile . > /dev/null 2>&1
	@echo "✓ Docker image built"
	@echo ""
	@echo "Step 4: Deploying to Docker Desktop Kubernetes..."
	@if kubectl cluster-info > /dev/null 2>&1; then \
		helm upgrade --install activable deploy/helm/activable -f deploy/helm/activable/values-local.yaml --wait --timeout 120s > /dev/null 2>&1 && echo "✓ Helm deployment successful" || echo "✗ Helm deployment failed"; \
	else \
		echo "⚠  Kubernetes not available. Infrastructure running (Postgres+AGE + Floci)."; \
		echo "    Enable K8s: Docker Desktop > Settings > Kubernetes > Enable"; \
	fi
	@echo ""
	@echo "=== Local Dev Environment Ready ==="
	@echo ""
	@echo "Services:"
	@echo "  Postgres+AGE:     localhost:5433"
	@echo "  Floci (AWS):      localhost:4566"
	@if kubectl cluster-info > /dev/null 2>&1; then \
		echo "  GraphQL API:      http://localhost:30080"; \
	fi
	@echo ""
	@echo "Next steps:"
	@echo "  make dev-seed      # Seed Floci with test AWS resources"
	@echo "  make dev-ingest    # Run the ingestion pipeline"
	@echo "  make dev-query     # Test the GraphQL API"

dev-down:
	@echo "Stopping local dev environment..."
	@if kubectl cluster-info > /dev/null 2>&1; then \
		echo "Step 1: Removing Kubernetes deployment..."; \
		helm uninstall activable 2>/dev/null || true; \
	fi
	@echo "Step 2: Stopping Docker Compose services..."
	docker compose -f $(COMPOSE_DEV) down
	@echo "✓ Dev environment stopped (volumes preserved)"

dev-reset:
	@echo "Resetting local dev environment (destroys all data)..."
	@if kubectl cluster-info > /dev/null 2>&1; then \
		helm uninstall activable 2>/dev/null || true; \
	fi
	docker compose -f $(COMPOSE_DEV) down -v
	docker volume rm activable-db-data-dev 2>/dev/null || true
	@echo "✓ Reset complete"
	@echo ""
	@echo "Starting fresh environment..."
	make dev-up

dev-seed:
	@echo "Seeding Floci with test AWS resources..."
	@if ! curl -s http://localhost:4566/ > /dev/null 2>&1; then \
		echo "✗ Floci not responding at localhost:4566"; \
		echo "  Run 'make dev-up' first"; \
		exit 1; \
	fi
	@bash infra/scripts/seed-floci.sh

dev-ingest: build
	@echo "Running ingestion against Floci..."
	@if ! curl -s http://localhost:4566/ > /dev/null 2>&1; then \
		echo "✗ Floci not responding"; \
		exit 1; \
	fi
	@if ! pg_isready -h localhost -p 5433 -U activable > /dev/null 2>&1; then \
		echo "✗ Postgres not responding"; \
		exit 1; \
	fi
	@echo "Step 1: Running ingesters (IAM, STS, S3, EC2, Lambda)..."
	ACTIVABLE_LOCAL_DEV=1 \
	AWS_ENDPOINT_URL=http://localhost:4566 \
	AWS_ACCESS_KEY_ID=test \
	AWS_SECRET_ACCESS_KEY=test \
	AWS_DEFAULT_REGION=us-east-1 \
	ACTIVABLE_DB_URL="postgres://activable:activable_dev@localhost:5433/activable?sslmode=disable" \
	ACTIVABLE_GRAPH_NAME=cloud \
	ACTIVABLE_BATCH_SIZE=500 \
	ACTIVABLE_REGIONS=us-east-1 \
	DYLD_LIBRARY_PATH=$(PWD)/target/release \
	LD_LIBRARY_PATH=$(PWD)/target/release \
	  go run ./go/cmd/activable ingest
	@echo "✓ Ingestion complete"

dev-query:
	@echo "Testing GraphQL API..."
	@if ! curl -s http://localhost:30080/ > /dev/null 2>&1; then \
		echo "✗ GraphQL API not responding at localhost:30080"; \
		echo "  Run 'make dev-up' and wait for K8s deployment"; \
		exit 1; \
	fi
	@QUERY='{ nodes { id label } }'; \
	curl -X POST http://localhost:30080/graphql \
		-H "Content-Type: application/json" \
		-d "{\"query\": \"$$QUERY\"}" 2>/dev/null | \
	if command -v jq > /dev/null 2>&1; then jq .; else cat; fi

dev-status:
	@echo "=== Infrastructure (Docker Compose) ==="
	docker compose -f $(COMPOSE_DEV) ps
	@echo ""
	@if kubectl cluster-info > /dev/null 2>&1; then \
		echo "=== Application (Kubernetes) ==="; \
		kubectl get pods -l app.kubernetes.io/name=activable 2>/dev/null || echo "No K8s pods running"; \
	fi
	@echo ""
	@echo "=== Service Health ==="
	@if curl -s http://localhost:4566/ > /dev/null 2>&1; then echo "✓ Floci (AWS): http://localhost:4566"; else echo "✗ Floci: not responding"; fi
	@if pg_isready -h localhost -p 5433 -U activable > /dev/null 2>&1; then echo "✓ Postgres+AGE: localhost:5433"; else echo "✗ Postgres: not responding"; fi
	@if [ -z "$(shell kubectl cluster-info 2>/dev/null)" ]; then \
		if curl -s http://localhost:30080/ > /dev/null 2>&1; then echo "✓ GraphQL API: http://localhost:30080"; else echo "✗ GraphQL: not responding"; fi; \
	fi

dev-logs:
	@echo "Tailing Docker Compose logs (Ctrl-C to stop)..."
	docker compose -f $(COMPOSE_DEV) logs -f
