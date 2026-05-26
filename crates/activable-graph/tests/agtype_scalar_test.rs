//! Tests for parse_agtype_scalar helper.
//!
//! Validates that the agtype scalar decoder handles:
//! - Bare numbers: "5" → 5
//! - Quoted forms: "\"5\"" → 5
//! - Edge cases: empty, non-numeric, JSON Object forms
//! - Branch coverage: all parse paths exercised
//!
//! Run with:
//!   cargo test --test agtype_scalar_test

use activable_graph::parse_agtype_scalar;

// ── Unit tests: bare numbers ────────────────────────────────────────────────

#[test]
fn test_parse_bare_number_u32() {
    let result = parse_agtype_scalar::<u32>("42");
    assert!(result.is_ok(), "bare u32 should parse");
    assert_eq!(result.unwrap(), 42);
}

#[test]
fn test_parse_bare_number_with_whitespace() {
    let result = parse_agtype_scalar::<u32>("  100  ");
    assert!(result.is_ok(), "u32 with whitespace should parse");
    assert_eq!(result.unwrap(), 100);
}

#[test]
fn test_parse_bare_number_zero() {
    let result = parse_agtype_scalar::<u32>("0");
    assert!(result.is_ok(), "bare zero should parse");
    assert_eq!(result.unwrap(), 0);
}

#[test]
fn test_parse_bare_number_large() {
    let result = parse_agtype_scalar::<u32>("4294967295");
    assert!(result.is_ok(), "max u32 should parse");
    assert_eq!(result.unwrap(), 4294967295);
}

#[test]
fn test_parse_bare_number_i32() {
    let result = parse_agtype_scalar::<i32>("-42");
    assert!(result.is_ok(), "negative i32 should parse");
    assert_eq!(result.unwrap(), -42);
}

#[test]
fn test_parse_bare_number_i64() {
    let result = parse_agtype_scalar::<i64>("9223372036854775807");
    assert!(result.is_ok(), "max i64 should parse");
    assert_eq!(result.unwrap(), 9223372036854775807);
}

// ── Unit tests: quoted forms ────────────────────────────────────────────────

#[test]
fn test_parse_double_quoted_number() {
    let result = parse_agtype_scalar::<u32>("\"42\"");
    assert!(result.is_ok(), "double-quoted number should parse");
    assert_eq!(result.unwrap(), 42);
}

#[test]
fn test_parse_single_quoted_number() {
    let result = parse_agtype_scalar::<u32>("'42'");
    assert!(result.is_ok(), "single-quoted number should parse");
    assert_eq!(result.unwrap(), 42);
}

#[test]
fn test_parse_quoted_with_whitespace() {
    let result = parse_agtype_scalar::<u32>("  \"  100  \"  ");
    assert!(result.is_ok(), "quoted number with whitespace should parse");
    assert_eq!(result.unwrap(), 100);
}

// ── Unit tests: edge cases (error paths) ────────────────────────────────────

#[test]
fn test_parse_empty_string() {
    let result = parse_agtype_scalar::<u32>("");
    assert!(result.is_err(), "empty string should error");
}

#[test]
fn test_parse_non_numeric() {
    let result = parse_agtype_scalar::<u32>("not_a_number");
    assert!(result.is_err(), "non-numeric should error");
}

#[test]
fn test_parse_quoted_non_numeric() {
    let result = parse_agtype_scalar::<u32>("\"not_a_number\"");
    assert!(result.is_err(), "quoted non-numeric should error");
}

#[test]
fn test_parse_overflow() {
    let result = parse_agtype_scalar::<u32>("5000000000");
    assert!(result.is_err(), "u32 overflow should error");
}

#[test]
fn test_parse_negative_to_unsigned() {
    let result = parse_agtype_scalar::<u32>("-1");
    assert!(result.is_err(), "negative to u32 should error");
}

// ── Unit tests: JSON Object forms ────────────────────────────────────────────

#[test]
fn test_parse_json_object_with_value_field() {
    let result = parse_agtype_scalar::<u32>("{\"value\": 42}");
    assert!(result.is_ok(), "JSON with value field should parse");
    assert_eq!(result.unwrap(), 42);
}

#[test]
fn test_parse_json_object_with_result_field() {
    let result = parse_agtype_scalar::<u32>("{\"result\": 100}");
    assert!(result.is_ok(), "JSON with result field should parse");
    assert_eq!(result.unwrap(), 100);
}

#[test]
fn test_parse_json_object_with_count_field() {
    let result = parse_agtype_scalar::<u32>("{\"count\": 50}");
    assert!(result.is_ok(), "JSON with count field should parse");
    assert_eq!(result.unwrap(), 50);
}

#[test]
fn test_parse_json_object_with_count_star_field() {
    let result = parse_agtype_scalar::<u32>("{\"count(*)\": 75}");
    assert!(result.is_ok(), "JSON with count(*) field should parse");
    assert_eq!(result.unwrap(), 75);
}

#[test]
fn test_parse_json_object_no_recognized_field() {
    let result = parse_agtype_scalar::<u32>("{\"other_field\": 42}");
    assert!(result.is_err(), "JSON without recognized field should error");
}

#[test]
fn test_parse_json_object_with_string_value() {
    let result = parse_agtype_scalar::<u32>("{\"value\": \"42\"}");
    assert!(result.is_err(), "JSON with string value should error");
}

#[test]
fn test_parse_invalid_json() {
    let result = parse_agtype_scalar::<u32>("{invalid json}");
    assert!(result.is_err(), "invalid JSON should error");
}

// ── Unit tests: bool parsing ────────────────────────────────────────────────

#[test]
fn test_parse_bool_true_bare() {
    let result = parse_agtype_scalar::<bool>("true");
    assert!(result.is_ok(), "bare true should parse");
    assert_eq!(result.unwrap(), true);
}

#[test]
fn test_parse_bool_false_bare() {
    let result = parse_agtype_scalar::<bool>("false");
    assert!(result.is_ok(), "bare false should parse");
    assert_eq!(result.unwrap(), false);
}

#[test]
fn test_parse_bool_quoted_true() {
    let result = parse_agtype_scalar::<bool>("\"true\"");
    assert!(result.is_ok(), "quoted true should parse");
    assert_eq!(result.unwrap(), true);
}

#[test]
fn test_parse_bool_invalid() {
    let result = parse_agtype_scalar::<bool>("maybe");
    assert!(result.is_err(), "invalid bool should error");
}

// ── Integration test: count(*) from relationship rule ────────────────────────

#[test]
fn test_relationship_count_bare_number() {
    let raw_result = "42";
    let count = parse_agtype_scalar::<u32>(raw_result);
    assert!(count.is_ok(), "relationship count should parse");
    assert_eq!(count.unwrap(), 42);
}

#[test]
fn test_relationship_count_zero() {
    let raw_result = "0";
    let count = parse_agtype_scalar::<u32>(raw_result);
    assert!(count.is_ok(), "zero count should be distinguishable from error");
    assert_eq!(count.unwrap(), 0);
}

#[test]
fn test_relationship_count_unparseable() {
    let raw_result = "not_a_count";
    let count = parse_agtype_scalar::<u32>(raw_result);
    assert!(count.is_err(), "unparseable count should error (not silent 0)");
}

#[test]
fn test_relationship_count_empty_result() {
    let raw_result = "";
    let count = parse_agtype_scalar::<u32>(raw_result);
    assert!(count.is_err(), "empty count should error");
}
