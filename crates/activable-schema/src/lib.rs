//! Activable schema — node and edge types for the cloud attack graph.
//!
//! Defines the core graph primitives: nodes (`IAM principals`, `resources`, etc.) and
//! edges (`AssumeRole`, `CanAccess`, etc.). Includes ARN canonicalization and serialization.

pub mod arn;

/// Returns the schema version string.
#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(version(), "0.1.0");
    }
}
