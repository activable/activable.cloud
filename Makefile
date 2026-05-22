.PHONY: setup lint test test-integration bindgen build ingest smoke verify verify-rust verify-go test-ffi-stability size-check spike-bench clean

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

test-integration:
	@echo "Running integration tests..."
	@echo "Step 1: Tearing down existing docker compose stack..."
	docker compose -f infra/compose/docker-compose.yml down -v || true
	@echo "Step 2: Starting postgres+AGE..."
	docker compose -f infra/compose/docker-compose.yml up -d
	@echo "Step 3: Waiting for postgres to be healthy..."
	@for i in 1 2 3 4 5 6; do \
		if docker compose -f infra/compose/docker-compose.yml ps db | grep -q "healthy"; then \
			echo "Postgres is healthy"; \
			break; \
		fi; \
		echo "Waiting... ($$i/6)"; \
		sleep 3; \
	done
	@echo "Step 4: Running Rust integration tests..."
	AGE_TEST_URL="postgresql://activable:activable_dev@localhost:5433/activable" \
	  rtk cargo test -p activable-graph --test integration -- --test-threads=1 --nocapture
	@echo "Step 5: Running Go integration tests..."
	ACTIVABLE_INTEGRATION=1 ACTIVABLE_DB_URL="postgresql://activable:activable_dev@localhost:5433/activable" \
	  rtk go test ./go/tests/integration/... -v
	@echo "Step 6: Cleaning up docker compose stack..."
	docker compose -f infra/compose/docker-compose.yml down -v
	@echo "Integration tests complete"

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
