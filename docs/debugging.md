# Debugging Guide — Rust + Go + UniFFI

Cross-language debugging can be tricky. This guide covers the most common issues and how to diagnose them.

## Panic Traces Across FFI Boundary

When Rust panics, the stack trace may not automatically propagate to Go. Here's how to capture it:

### 1. Set Rust Backtrace

```bash
RUST_BACKTRACE=1 ./go/bin/activable verify
RUST_BACKTRACE=full ./go/bin/activable verify  # Full backtrace with library info
```

### 2. Examine Panic Output

Rust panics are printed to `stderr`:
```bash
./go/bin/activable verify 2>&1 | grep -A 50 "panicked at"
```

### 3. Decode Backtrace (if compiled with symbols)

If the binary was built in debug mode with symbols:
```bash
RUST_BACKTRACE=full ./go/bin/activable verify 2>&1 > panic.log
# Line numbers in panic.log correspond to src/ files
```

## GDB Attach — Segfaults in UniFFI Bindings

If the Go binary segfaults when calling Rust (exit code 139 or similar):

### 1. Build Rust with Debug Symbols

```bash
cargo build --workspace  # Default is debug mode
```

### 2. Run under GDB

```bash
# On macOS
lldb ./go/bin/activable
(lldb) run verify
# Will break on segfault; use `bt` for backtrace

# On Linux
gdb ./go/bin/activable
(gdb) run verify
(gdb) bt  # Full backtrace
(gdb) frame <N>  # Inspect specific frame
(gdb) p $rax  # Print registers
```

### 3. Common Segfault Causes

| Cause | Symptom | Fix |
|-------|---------|-----|
| Uninitialized dylib | Instant segfault on first FFI call | Run `make build` to compile Rust library |
| Rust panic in unsafe FFI | Segfault during call | Enable `RUST_BACKTRACE` to see panic |
| Go goroutine + unsafe FFI | Race condition / double-free | Ensure FFI function is `Send + Sync` |
| Wrong dylib path | "Library not found" or segfault on invocation | Check `make bindgen` output; verify `.so`/`.dylib` exists |

## Bindgen Failures

### 1. "uniffi-bindgen-go: not found"

Install the generator:
```bash
cargo install uniffi_bindgen --version 0.31.0
```

Or use the workspace crate's version:
```bash
cargo run --manifest-path crates/activable-ffi/Cargo.toml --bin uniffi-bindgen-go -- --help
```

### 2. "UDL parse error"

Check `crates/activable-ffi/src/activable.udl` syntax:
```bash
cat crates/activable-ffi/src/activable.udl | head -20
```

Common mistakes:
- Missing semicolons at end of function declarations
- Wrong type annotations (use `string`, not `String`)
- Namespace not matching crate name

### 3. Generated .go files won't compile

Run `go mod tidy` and check for import errors:
```bash
cd go
go mod tidy
go vet ./...
```

If bindings use undefined types, the UDL is incomplete. Example:
```
// ❌ Bad UDL (Go doesn't know what `Arn` is)
namespace activable {
    Arn parse_arn(string input);
};

// ✅ Good UDL (expose simple types only; complex types deferred)
namespace activable {
    string version();
};
```

## Platform-Specific Issues

### macOS: "dylib not found"

```bash
# Verify dylib was built
ls -la target/release/libactivable_ffi.dylib

# Check dylib paths
otool -L target/release/libactivable_ffi.dylib

# Ensure CGO finds it
export DYLD_LIBRARY_PATH="$(pwd)/target/release:$DYLD_LIBRARY_PATH"
go test ./go/...
```

### Linux: "libactivable_ffi.so.0: cannot open shared object"

```bash
# Verify .so was built
ls -la target/release/libactivable_ffi.so

# Check rpath
readelf -d target/release/libactivable_ffi.so | grep RPATH

# Or set LD_LIBRARY_PATH
export LD_LIBRARY_PATH="$(pwd)/target/release:$LD_LIBRARY_PATH"
go test ./go/...
```

### Windows: MSVC toolchain mismatch

```bash
# Ensure Rust uses MSVC
rustup override set stable-msvc

# Rebuild
cargo build --workspace --release
```

## Race Conditions in FFI Tests

When running `go test -race ./...` against FFI bindings, race detector may report false positives if Rust functions are marked `unsafe` in Go.

**Safe approach:**
- Ensure all exported Rust functions via UniFFI are threadsafe (`Send + Sync`)
- Test concurrency with explicit goroutines:

```go
func TestFfiConcurrent(t *testing.T) {
    const numGoroutines = 100
    const callsPerGoroutine = 1000

    errors := make(chan error, numGoroutines)
    for i := 0; i < numGoroutines; i++ {
        go func() {
            for j := 0; j < callsPerGoroutine; j++ {
                v := activable.Version()
                if v == "" {
                    errors <- fmt.Errorf("empty version")
                    return
                }
            }
            errors <- nil
        }()
    }

    for i := 0; i < numGoroutines; i++ {
        if err := <-errors; err != nil {
            t.Fatalf("goroutine failed: %v", err)
        }
    }
}
```

## Profiling Across FFI Boundary

See [profiling.md](./profiling.md) for cross-FFI flame graphs and pprof analysis.

## Checklist for New FFI Calls

Before adding a new Rust function to the FFI:

- [ ] Function is `pub` and marked with `#[uniffi::export]`
- [ ] Function parameters use simple types (string, u64, etc.) — avoid complex structs (deferred)
- [ ] UDL declaration matches the Rust signature
- [ ] Run `make bindgen` and verify `.go` compiles
- [ ] Run `cargo test && go test -race ./...`
- [ ] Add a brief test in `crates/activable-ffi/tests/ffi_smoke.rs`

## Logs & Traces

### Rust Logging

Use `log` crate or `tracing`:
```bash
RUST_LOG=debug cargo run
```

### Go Logging

Use structured logging (JSON format):
```go
import "github.com/rs/zerolog/log"

log.Info().Str("module", "ingest").Msg("starting ingest")
```

### OpenTelemetry

OTel integration is not yet implemented. For now, use `println!` or `log` in Rust and `zerolog` in Go.

---

**Still stuck?** Open an issue on GitHub or reach out to maintainers.
