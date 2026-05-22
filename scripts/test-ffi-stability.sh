#!/bin/bash
# FFI stability test: concurrent stress test of UniFFI bindings.
# Runs 100+ concurrent goroutines calling Rust version() function.
#
# Canonical invocation point for `make test-ffi-stability` and the
# `ffi-stability` CI job. CGo linker env is set here so callers
# (Makefile, CI) do not need to duplicate it.

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Check if the Rust library is built
if [ ! -f "$REPO_ROOT/target/release/libactivable_ffi.dylib" ] && \
   [ ! -f "$REPO_ROOT/target/release/libactivable_ffi.so" ]; then
    echo "Error: Rust FFI library not found. Run 'make build' first."
    exit 1
fi

echo "Running FFI stability test (100+ concurrent goroutines calling Rust version())..."

# Set linker env for both Linux (LD_LIBRARY_PATH) and macOS (DYLD_LIBRARY_PATH).
export DYLD_LIBRARY_PATH="$REPO_ROOT/target/release${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
export LD_LIBRARY_PATH="$REPO_ROOT/target/release${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export CGO_LDFLAGS="-L$REPO_ROOT/target/release"

# Concurrent test runner via go test -race
go test -race -count=10 -timeout=60s -run TestConcurrentFFI "$REPO_ROOT/go/cmd/activable" || {
    echo "Error: FFI stability test failed"
    exit 1
}

echo "OK: FFI stability test passed"
exit 0
