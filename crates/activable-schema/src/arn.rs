//! ARN parsing and canonicalization.
//!
//! Parses AWS ARNs into canonical form for consistent graph node identity.
//! Implements full ARN field validation per AWS ARN specification.

use std::fmt;

/// Represents a parsed AWS ARN in canonical form.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Arn {
    /// The partition (aws, aws-cn, aws-us-gov).
    pub partition: String,
    /// The service (iam, ec2, s3, etc.).
    pub service: String,
    /// The AWS region.
    pub region: String,
    /// The AWS account ID.
    pub account: String,
    /// The resource type and identifier.
    pub resource: String,
}

impl Arn {
    /// Parses an ARN string into canonical form.
    ///
    /// ARN format: `arn:<partition>:<service>:<region>:<account>:<resource>`
    ///
    /// Validation rules:
    /// - Index 0 must be literal "arn"
    /// - Index 1 (partition): lowercased; must be one of {aws, aws-cn, aws-us-gov}
    /// - Index 2 (service): lowercased; must not be empty
    /// - Index 3 (region): lowercased; empty string is valid (global services)
    /// - Index 4 (account): empty string, "aws", or exactly 12 ASCII digits
    /// - Index 5 (resource): preserved as-is (case-sensitive); must not be empty
    ///
    /// # Errors
    /// Returns a descriptive error message for any validation failure.
    pub fn parse(s: &str) -> Result<Self, String> {
        if s.is_empty() {
            return Err("ARN string is empty".to_string());
        }

        let parts: Vec<&str> = s.splitn(6, ':').collect();

        if parts.len() != 6 {
            return Err(format!(
                "ARN must have exactly 6 colon-separated parts, got {}",
                parts.len()
            ));
        }

        // Index 0: literal "arn"
        if parts[0] != "arn" {
            return Err(format!("ARN must start with 'arn:', got '{}'", parts[0]));
        }

        // Index 1: partition (validate against whitelist)
        let partition = parts[1].to_lowercase();
        if !matches!(partition.as_str(), "aws" | "aws-cn" | "aws-us-gov") {
            return Err(format!(
                "Unknown ARN partition '{}'; must be one of {{aws, aws-cn, aws-us-gov}}",
                partition
            ));
        }

        // Index 2: service (must not be empty)
        let service = parts[2].to_lowercase();
        if service.is_empty() {
            return Err("ARN service field must not be empty".to_string());
        }

        // Index 3: region (lowercase; empty is valid)
        let region = parts[3].to_lowercase();

        // Index 4: account (empty, "aws", or exactly 12 digits)
        let account = parts[4];
        if !account.is_empty()
            && account != "aws"
            && (account.len() != 12 || !account.chars().all(|c| c.is_ascii_digit()))
        {
            return Err(format!(
                "ARN account must be empty, 'aws', or exactly 12 digits, got '{}'",
                account
            ));
        }
        let account = account.to_string();

        // Index 5: resource (preserve case; must not be empty)
        let resource = parts[5];
        if resource.is_empty() {
            return Err("ARN resource field must not be empty".to_string());
        }
        let resource = resource.to_string();

        Ok(Self {
            partition,
            service,
            region,
            account,
            resource,
        })
    }

    /// Returns the canonical string form of the ARN.
    #[must_use]
    pub fn canonical(&self) -> String {
        format!(
            "arn:{}:{}:{}:{}:{}",
            self.partition, self.service, self.region, self.account, self.resource
        )
    }
}

impl fmt::Display for Arn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.canonical())
    }
}

/// Validates that a string is a valid ARN that can be used as a graph node ID.
///
/// Returns true if:
/// - The string parses as a valid ARN
/// - The resource field does not contain wildcard characters ('*' or '?')
///
/// Returns false otherwise (non-ARN strings, parse errors, or wildcard resources).
#[must_use]
pub fn is_valid_node_id(s: &str) -> bool {
    match Arn::parse(s) {
        Ok(arn) => !arn.resource.contains('*') && !arn.resource.contains('?'),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestCase {
        input: &'static str,
        should_parse: bool,
        expected_partition: Option<&'static str>,
        expected_service: Option<&'static str>,
        expected_region: Option<&'static str>,
        expected_account: Option<&'static str>,
        expected_resource: Option<&'static str>,
        is_valid_node_id: Option<bool>,
    }

    #[test]
    fn test_arn_corpus() {
        let test_cases = vec![
            // Case 1: IAM user with all fields
            TestCase {
                input: "arn:aws:iam::123456789012:user/alice",
                should_parse: true,
                expected_partition: Some("aws"),
                expected_service: Some("iam"),
                expected_region: Some(""),
                expected_account: Some("123456789012"),
                expected_resource: Some("user/alice"),
                is_valid_node_id: Some(true),
            },
            // Case 2: AWS-managed policy (account="aws")
            TestCase {
                input: "arn:aws:iam::aws:policy/AdministratorAccess",
                should_parse: true,
                expected_partition: Some("aws"),
                expected_service: Some("iam"),
                expected_region: Some(""),
                expected_account: Some("aws"),
                expected_resource: Some("policy/AdministratorAccess"),
                is_valid_node_id: Some(true),
            },
            // Case 3: S3 bucket (no region, no account)
            TestCase {
                input: "arn:aws:s3:::my-bucket",
                should_parse: true,
                expected_partition: Some("aws"),
                expected_service: Some("s3"),
                expected_region: Some(""),
                expected_account: Some(""),
                expected_resource: Some("my-bucket"),
                is_valid_node_id: Some(true),
            },
            // Case 4: STS assumed-role session (resource contains colons)
            TestCase {
                input: "arn:aws:sts::123456789012:assumed-role/Role/Session",
                should_parse: true,
                expected_partition: Some("aws"),
                expected_service: Some("sts"),
                expected_region: Some(""),
                expected_account: Some("123456789012"),
                expected_resource: Some("assumed-role/Role/Session"),
                is_valid_node_id: Some(true),
            },
            // Case 5: IAM role with path
            TestCase {
                input: "arn:aws:iam::123456789012:role/path/to/role",
                should_parse: true,
                expected_partition: Some("aws"),
                expected_service: Some("iam"),
                expected_region: Some(""),
                expected_account: Some("123456789012"),
                expected_resource: Some("role/path/to/role"),
                is_valid_node_id: Some(true),
            },
            // Case 6: China partition EC2
            TestCase {
                input: "arn:aws-cn:ec2:cn-north-1:123456789012:instance/i-abc",
                should_parse: true,
                expected_partition: Some("aws-cn"),
                expected_service: Some("ec2"),
                expected_region: Some("cn-north-1"),
                expected_account: Some("123456789012"),
                expected_resource: Some("instance/i-abc"),
                is_valid_node_id: Some(true),
            },
            // Case 7: Wildcard resource (parses OK, but invalid node ID)
            TestCase {
                input: "arn:aws:s3:::*",
                should_parse: true,
                expected_partition: Some("aws"),
                expected_service: Some("s3"),
                expected_region: Some(""),
                expected_account: Some(""),
                expected_resource: Some("*"),
                is_valid_node_id: Some(false),
            },
            // Case 8: Non-ARN string
            TestCase {
                input: "not-an-arn",
                should_parse: false,
                expected_partition: None,
                expected_service: None,
                expected_region: None,
                expected_account: None,
                expected_resource: None,
                is_valid_node_id: Some(false),
            },
            // Case 9: GovCloud partition
            TestCase {
                input: "arn:aws-us-gov:iam::123456789012:role/test",
                should_parse: true,
                expected_partition: Some("aws-us-gov"),
                expected_service: Some("iam"),
                expected_region: Some(""),
                expected_account: Some("123456789012"),
                expected_resource: Some("role/test"),
                is_valid_node_id: Some(true),
            },
            // Case 10: Mixed-case service field (must normalize to lowercase)
            TestCase {
                input: "arn:aws:IAM::123456789012:user/alice",
                should_parse: true,
                expected_partition: Some("aws"),
                expected_service: Some("iam"),
                expected_region: Some(""),
                expected_account: Some("123456789012"),
                expected_resource: Some("user/alice"),
                is_valid_node_id: Some(true),
            },
            // Case 11: Unknown partition
            TestCase {
                input: "arn:aws-fake:iam::123456789012:user/alice",
                should_parse: false,
                expected_partition: None,
                expected_service: None,
                expected_region: None,
                expected_account: None,
                expected_resource: None,
                is_valid_node_id: Some(false),
            },
            // Case 12: Account with letters (invalid)
            TestCase {
                input: "arn:aws:iam::1234abcd5678:user/alice",
                should_parse: false,
                expected_partition: None,
                expected_service: None,
                expected_region: None,
                expected_account: None,
                expected_resource: None,
                is_valid_node_id: Some(false),
            },
        ];

        for (idx, case) in test_cases.iter().enumerate() {
            let result = Arn::parse(case.input);
            if case.should_parse {
                assert!(
                    result.is_ok(),
                    "Test case {}: expected '{}' to parse successfully, got error: {:?}",
                    idx + 1,
                    case.input,
                    result.err()
                );
                let arn = result.unwrap();

                // Verify individual fields
                if let Some(exp_partition) = case.expected_partition {
                    assert_eq!(
                        arn.partition,
                        exp_partition,
                        "Test case {}: partition mismatch",
                        idx + 1
                    );
                }
                if let Some(exp_service) = case.expected_service {
                    assert_eq!(
                        arn.service,
                        exp_service,
                        "Test case {}: service mismatch",
                        idx + 1
                    );
                }
                if let Some(exp_region) = case.expected_region {
                    assert_eq!(
                        arn.region,
                        exp_region,
                        "Test case {}: region mismatch",
                        idx + 1
                    );
                }
                if let Some(exp_account) = case.expected_account {
                    assert_eq!(
                        arn.account,
                        exp_account,
                        "Test case {}: account mismatch",
                        idx + 1
                    );
                }
                if let Some(exp_resource) = case.expected_resource {
                    assert_eq!(
                        arn.resource,
                        exp_resource,
                        "Test case {}: resource mismatch",
                        idx + 1
                    );
                }

                // Verify canonical round-trip
                let canonical = arn.canonical();
                let reparsed = Arn::parse(&canonical);
                assert!(
                    reparsed.is_ok(),
                    "Test case {}: canonical form should re-parse successfully",
                    idx + 1
                );
                assert_eq!(
                    arn,
                    reparsed.unwrap(),
                    "Test case {}: canonical round-trip mismatch",
                    idx + 1
                );
            } else {
                assert!(
                    result.is_err(),
                    "Test case {}: expected '{}' to fail parsing, but succeeded",
                    idx + 1,
                    case.input
                );
                // Verify error message is non-empty
                let err_msg = result.unwrap_err();
                assert!(
                    !err_msg.is_empty(),
                    "Test case {}: error message must not be empty",
                    idx + 1
                );
            }

            // Verify is_valid_node_id behavior
            if let Some(expected) = case.is_valid_node_id {
                let actual = is_valid_node_id(case.input);
                assert_eq!(
                    actual,
                    expected,
                    "Test case {}: is_valid_node_id('{}') expected {}, got {}",
                    idx + 1,
                    case.input,
                    expected,
                    actual
                );
            }
        }
    }

    #[test]
    fn test_arn_resource_with_embedded_colons() {
        // Ensure splitn(6, ':') captures colons in the resource field
        let arn = Arn::parse("arn:aws:sts::123456789012:assumed-role/MyRole/MySession").unwrap();
        assert_eq!(arn.resource, "assumed-role/MyRole/MySession");
        // This would fail with split(':') because it would split the resource
        // but splitn(6, ':') correctly preserves everything after the 5th colon
    }

    #[test]
    fn test_arn_resource_with_multiple_colons() {
        let arn =
            Arn::parse("arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/MyFunction:*")
                .unwrap();
        assert_eq!(arn.service, "logs");
        assert_eq!(arn.resource, "log-group:/aws/lambda/MyFunction:*");
    }

    #[test]
    fn test_arn_case_preservation_in_resource() {
        // S3 bucket names are case-sensitive in the resource field
        let arn = Arn::parse("arn:aws:s3:::MyBucket").unwrap();
        assert_eq!(arn.resource, "MyBucket");

        // But partition, service normalized to lowercase
        assert_eq!(arn.partition, "aws");
        assert_eq!(arn.service, "s3");
    }

    #[test]
    fn test_arn_mixed_case_partition_normalized() {
        let arn = Arn::parse("arn:AWS:iam::123456789012:user/alice").unwrap();
        assert_eq!(arn.partition, "aws");
    }

    #[test]
    fn test_arn_mixed_case_service_normalized() {
        let arn = Arn::parse("arn:aws:IAM::123456789012:user/alice").unwrap();
        assert_eq!(arn.service, "iam");
    }

    #[test]
    fn test_arn_empty_string_fails() {
        let result = Arn::parse("");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty"));
    }

    #[test]
    fn test_arn_too_few_parts_fails() {
        let result = Arn::parse("arn:aws:iam::user");
        assert!(result.is_err());
    }

    #[test]
    fn test_arn_unknown_partition_rejected() {
        let result = Arn::parse("arn:aws-custom:iam::123456789012:user/alice");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown ARN partition"));
    }

    #[test]
    fn test_arn_empty_service_rejected() {
        let result = Arn::parse("arn:aws:::123456789012:user/alice");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("service field must not be empty"));
    }

    #[test]
    fn test_arn_invalid_account_with_letters() {
        let result = Arn::parse("arn:aws:iam::12345abc6789:user/alice");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exactly 12 digits"));
    }

    #[test]
    fn test_arn_invalid_account_too_short() {
        let result = Arn::parse("arn:aws:iam::12345:user/alice");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exactly 12 digits"));
    }

    #[test]
    fn test_arn_invalid_account_too_long() {
        let result = Arn::parse("arn:aws:iam::1234567890123:user/alice");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exactly 12 digits"));
    }

    #[test]
    fn test_arn_empty_resource_rejected() {
        let result = Arn::parse("arn:aws:iam::123456789012:");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("resource field must not be empty"));
    }

    #[test]
    fn test_is_valid_node_id_rejects_wildcards_asterisk() {
        assert!(!is_valid_node_id("arn:aws:s3:::*"));
        assert!(!is_valid_node_id("arn:aws:iam::123456789012:user/*"));
    }

    #[test]
    fn test_is_valid_node_id_rejects_wildcards_question() {
        assert!(!is_valid_node_id("arn:aws:iam::123456789012:user/alice?"));
    }

    #[test]
    fn test_is_valid_node_id_accepts_valid_arns() {
        assert!(is_valid_node_id("arn:aws:iam::123456789012:user/alice"));
        assert!(is_valid_node_id(
            "arn:aws:iam::aws:policy/AdministratorAccess"
        ));
        assert!(is_valid_node_id("arn:aws:s3:::my-bucket"));
    }

    #[test]
    fn test_is_valid_node_id_rejects_non_arns() {
        assert!(!is_valid_node_id("not-an-arn"));
        assert!(!is_valid_node_id("arn:invalid:parts"));
        assert!(!is_valid_node_id(""));
    }

    #[test]
    fn test_arn_canonical_format() {
        let arn = Arn::parse("arn:aws:iam::123456789012:user/alice").unwrap();
        assert_eq!(arn.canonical(), "arn:aws:iam::123456789012:user/alice");
    }

    #[test]
    fn test_arn_display_uses_canonical() {
        let arn = Arn::parse("arn:aws:s3:::my-bucket").unwrap();
        assert_eq!(format!("{}", arn), "arn:aws:s3:::my-bucket");
    }

    #[test]
    fn test_arn_partition_aws_cn_valid() {
        let arn = Arn::parse("arn:aws-cn:ec2:cn-north-1:123456789012:instance/i-abc").unwrap();
        assert_eq!(arn.partition, "aws-cn");
    }

    #[test]
    fn test_arn_partition_aws_us_gov_valid() {
        let arn = Arn::parse("arn:aws-us-gov:iam::123456789012:role/test").unwrap();
        assert_eq!(arn.partition, "aws-us-gov");
    }

    #[test]
    fn test_arn_account_aws_special_case() {
        let arn = Arn::parse("arn:aws:iam::aws:policy/Service-LinkedRolePolicy").unwrap();
        assert_eq!(arn.account, "aws");
    }

    #[test]
    fn test_arn_empty_account_valid() {
        let arn = Arn::parse("arn:aws:s3:::bucket").unwrap();
        assert_eq!(arn.account, "");
    }

    #[test]
    fn test_arn_equality_and_hash() {
        let arn1 = Arn::parse("arn:aws:iam::123456789012:user/alice").unwrap();
        let arn2 = Arn::parse("arn:aws:iam::123456789012:user/alice").unwrap();
        assert_eq!(arn1, arn2);
        // Hash should be the same for equal values
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(arn1);
        assert!(set.contains(&arn2));
    }
}
