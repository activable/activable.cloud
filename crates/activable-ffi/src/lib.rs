//! UniFFI surface for activable — FFI boundary between Rust and Go.

use activable_schema as schema;

/// Returns version string from the schema crate.
#[uniffi::export]
pub fn version() -> String {
    format!("activable v{}", schema::version())
}

uniffi::setup_scaffolding!();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_ffi() {
        let v = version();
        assert!(v.contains("activable"));
        assert!(v.contains("0.1.0"));
    }
}
