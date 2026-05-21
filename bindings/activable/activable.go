package activable

import "github.com/activable-cloud/activable.cloud/bindings/activable_ffi"

// Version returns the activable schema version string from the Rust FFI.
//
// This function calls into the native Rust library (libactivable_ffi)
// via the UniFFI interface. It is thread-safe and can be called
// concurrently from multiple goroutines.
//
// The return value is the schema version in the format "activable vX.Y.Z".
func Version() string {
	return activable_ffi.Version()
}
