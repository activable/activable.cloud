//! Smoke test for schema crate version.

#[test]
fn test_schema_version() {
    assert_eq!(activable_schema::version(), "0.1.0");
}
