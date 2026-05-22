#!/bin/bash
# FFI stability test: concurrent stress test of UniFFI bindings.
# Runs 100+ concurrent goroutines calling Rust version() function.

set -e

# Check if the Rust library is built
if [ ! -f "target/release/libactivable_ffi.dylib" ] && [ ! -f "target/release/libactivable_ffi.so" ]; then
    echo "Error: Rust FFI library not found. Run 'make build' first."
    exit 1
fi

# Check if Go binary is built
if [ ! -f "go/bin/activable" ]; then
    echo "Error: Go binary not found. Run 'make build' first."
    exit 1
fi

echo "Running FFI stability test (100+ concurrent goroutines calling Rust version())..."

# Concurrent test runner via go test -race
go test -race -count=10 -timeout=60s ./go/cmd/activable/... || {
    echo "Error: FFI stability test failed"
    exit 1
}

echo "OK: FFI stability test passed"
exit 0
