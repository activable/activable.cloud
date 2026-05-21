.PHONY: setup lint test test-integration bindgen build ingest verify test-ffi-stability size-check clean

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
	@echo "Integration tests (stub — populated Phase 6)"

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
	@echo "Error: ingest not yet implemented (Phase 4)"
	@exit 1

verify:
	@echo "Running smoke test..."
	@if [ ! -f go/bin/activable ]; then echo "Binary not found; run 'make build' first"; exit 1; fi
	DYLD_LIBRARY_PATH=$(PWD)/target/release LD_LIBRARY_PATH=$(PWD)/target/release go/bin/activable verify
	@echo "Smoke test passed"

test-ffi-stability:
	@echo "Running FFI stability test (concurrent goroutines)..."
	@if [ ! -f target/release/libactivable_ffi$(RUST_DYLIB_EXT) ]; then echo "Rust library not found; run 'make build' first"; exit 1; fi
	@echo "Running 100+ concurrent goroutine FFI calls via TestConcurrentFFI..."
	@go test -race -count=10 -timeout=60s -run TestConcurrentFFI ./go/cmd/activable
	@echo "FFI stability test passed"

size-check:
	@echo "Checking binary size..."
	@bash scripts/size-check.sh go/bin/activable

clean:
	cargo clean
	rm -rf go/bin target/
	find . -name "*.o" -delete
	@echo "Clean complete"
