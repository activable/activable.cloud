# UniFFI Go Bindings

This directory contains the **committed** UniFFI-generated Go bindings for the Rust FFI surface.

## Regenerating Bindings

To regenerate bindings after modifying `crates/activable-ffi/src/activable.udl` or adding new exported Rust functions:

```bash
make bindgen
```

The build process will:
1. Compile the Rust `activable-ffi` crate to a platform-specific dylib (`.so`, `.dylib`, or `.dll`).
2. Run `uniffi-bindgen-go` to generate Go bindings.
3. Replace the contents of `bindings/activable/` with the newly generated files.

## Platform Detection

The `Makefile` automatically detects the platform and uses the correct library file:
- **Linux:** `target/release/libactivable_ffi.so`
- **macOS:** `target/release/libactivable_ffi.dylib`
- **Windows:** `target/release/activable_ffi.dll`

## Troubleshooting

If `uniffi-bindgen-go` is not found, ensure it is installed:

```bash
cargo install uniffi_bindgen --version 0.31.0
```

Or use the Cargo-invoked binary from the uniffi crate:

```bash
cargo run --manifest-path crates/activable-ffi/Cargo.toml --bin uniffi-bindgen-go -- --library ...
```

## Committed Bindings

The `.go` and `_test.go` files in `bindings/activable/` are committed to the repository to:
- Make CI builds deterministic (no code generation during CI).
- Enable diffs to catch API changes.
- Allow go mod resolution without a Rust build step.

**Do not manually edit** these files; regenerate them via `make bindgen`.
