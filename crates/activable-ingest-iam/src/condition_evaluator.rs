//! Condition evaluator for AWS IAM policy conditions.
//!
//! Evaluates the top 6 condition operators:
//! - StringEquals, StringNotEquals, StringLike, StringNotLike
//! - ArnLike, ArnNotLike
//! - IpAddress, NotIpAddress
//! - Null, Bool
//!
//! Unknown operators log a warning and return `true` (not denied).

use crate::action_matcher::action_matches;
use crate::resource_matcher::resource_matches;
use std::net::IpAddr;

/// Evaluate a single condition against an actual value.
///
/// Returns `true` if the condition evaluates to true (matches).
/// Returns `false` if the condition evaluates to false (does not match).
/// Unknown operators return `true` with a warning log.
///
/// # Arguments
/// - `operator`: The condition operator (e.g., "StringEquals", "IpAddress")
/// - `key`: The condition key (e.g., "aws:RequestedRegion")
/// - `values`: The values to match against (AWS policy condition format)
/// - `actual_value`: The actual value from the request context
pub fn evaluate_condition(operator: &str, _key: &str, values: &[&str], actual_value: &str) -> bool {
    match operator {
        "StringEquals" => {
            // Match if actual_value equals ANY value in the list (OR semantics)
            values.iter().any(|v| actual_value.eq_ignore_ascii_case(v))
        }
        "StringNotEquals" => {
            // Match if actual_value does NOT equal ALL values (i.e., not in the list)
            values.iter().all(|v| !actual_value.eq_ignore_ascii_case(v))
        }
        "StringLike" => {
            // Wildcard match using action_matcher logic
            values.iter().any(|pattern| action_matches(pattern, actual_value))
        }
        "StringNotLike" => {
            // Match if actual_value does NOT match ANY pattern
            values.iter().all(|pattern| !action_matches(pattern, actual_value))
        }
        "ArnLike" => {
            // ARN wildcard match using resource_matcher logic
            values.iter().any(|pattern| resource_matches(pattern, actual_value))
        }
        "ArnNotLike" => {
            // Match if actual_value does NOT match ANY pattern
            values.iter().all(|pattern| !resource_matches(pattern, actual_value))
        }
        "IpAddress" => {
            // Parse actual_value as IP, check if it's in any CIDR block
            if let Ok(ip) = actual_value.parse::<IpAddr>() {
                values.iter().any(|cidr_str| {
                    if let Ok(cidr) = cidr_str.parse::<ipnet::IpNet>() {
                        cidr.contains(&ip)
                    } else {
                        false
                    }
                })
            } else {
                false
            }
        }
        "NotIpAddress" => {
            // Match if actual_value is NOT in ANY CIDR block
            if let Ok(ip) = actual_value.parse::<IpAddr>() {
                values.iter().all(|cidr_str| {
                    if let Ok(cidr) = cidr_str.parse::<ipnet::IpNet>() {
                        !cidr.contains(&ip)
                    } else {
                        true // unparseable CIDR is treated as not matching
                    }
                })
            } else {
                true // unparseable IP is treated as not in any CIDR
            }
        }
        "Null" => {
            // Null: "true" if actual_value is empty (key is absent), "false" if present
            let target = values.first().copied().unwrap_or("false");
            let is_absent = actual_value.is_empty();
            if target == "true" {
                is_absent
            } else {
                !is_absent
            }
        }
        "Bool" => {
            // Bool: direct string comparison of "true" or "false"
            values.iter().any(|v| actual_value.eq_ignore_ascii_case(v))
        }
        _ => {
            // Unknown operator: warn and default to not-denied
            tracing::warn!("unsupported condition operator: {}", operator);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_equals() {
        assert!(evaluate_condition("StringEquals", "region", &["us-east-1"], "us-east-1"));
        assert!(!evaluate_condition("StringEquals", "region", &["us-east-1"], "us-west-2"));
    }

    #[test]
    fn test_string_equals_case_insensitive() {
        assert!(evaluate_condition("StringEquals", "region", &["US-EAST-1"], "us-east-1"));
    }

    #[test]
    fn test_string_not_equals() {
        assert!(evaluate_condition(
            "StringNotEquals",
            "region",
            &["us-east-1"],
            "us-west-2"
        ));
        assert!(!evaluate_condition(
            "StringNotEquals",
            "region",
            &["us-east-1"],
            "us-east-1"
        ));
    }

    #[test]
    fn test_string_like() {
        assert!(evaluate_condition("StringLike", "prefix", &["home/*"], "home/alice/doc"));
        assert!(!evaluate_condition("StringLike", "prefix", &["home/*"], "work/bob"));
    }

    #[test]
    fn test_string_not_like() {
        assert!(evaluate_condition(
            "StringNotLike",
            "prefix",
            &["home/*"],
            "work/bob"
        ));
        assert!(!evaluate_condition(
            "StringNotLike",
            "prefix",
            &["home/*"],
            "home/alice/doc"
        ));
    }

    #[test]
    fn test_arn_like() {
        assert!(evaluate_condition(
            "ArnLike",
            "arn",
            &["arn:aws:s3:::my-*"],
            "arn:aws:s3:::my-bucket"
        ));
        assert!(!evaluate_condition(
            "ArnLike",
            "arn",
            &["arn:aws:s3:::my-*"],
            "arn:aws:s3:::other"
        ));
    }

    #[test]
    fn test_arn_not_like() {
        assert!(evaluate_condition(
            "ArnNotLike",
            "arn",
            &["arn:aws:s3:::my-*"],
            "arn:aws:s3:::other"
        ));
        assert!(!evaluate_condition(
            "ArnNotLike",
            "arn",
            &["arn:aws:s3:::my-*"],
            "arn:aws:s3:::my-bucket"
        ));
    }

    #[test]
    fn test_ip_address() {
        assert!(evaluate_condition(
            "IpAddress",
            "ip",
            &["10.0.0.0/8"],
            "10.1.2.3"
        ));
        assert!(!evaluate_condition(
            "IpAddress",
            "ip",
            &["10.0.0.0/8"],
            "192.168.1.1"
        ));
    }

    #[test]
    fn test_not_ip_address() {
        assert!(evaluate_condition(
            "NotIpAddress",
            "ip",
            &["10.0.0.0/8"],
            "192.168.1.1"
        ));
        assert!(!evaluate_condition(
            "NotIpAddress",
            "ip",
            &["10.0.0.0/8"],
            "10.1.2.3"
        ));
    }

    #[test]
    fn test_null_true() {
        assert!(evaluate_condition("Null", "mfa", &["true"], ""));
        assert!(!evaluate_condition("Null", "mfa", &["true"], "3600"));
    }

    #[test]
    fn test_null_false() {
        assert!(evaluate_condition("Null", "mfa", &["false"], "3600"));
        assert!(!evaluate_condition("Null", "mfa", &["false"], ""));
    }

    #[test]
    fn test_bool() {
        assert!(evaluate_condition("Bool", "secure", &["true"], "true"));
        assert!(!evaluate_condition("Bool", "secure", &["true"], "false"));
    }

    #[test]
    fn test_unknown_operator() {
        assert!(evaluate_condition(
            "DateLessThan",
            "time",
            &["2026-12-31"],
            "2026-06-15"
        ));
    }
}
