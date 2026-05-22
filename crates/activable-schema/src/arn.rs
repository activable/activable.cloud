//! ARN parsing and canonicalization.
//!
//! Parses AWS ARNs into canonical form for consistent graph node identity.
//! Validates partitions, services, regions, accounts, and resource formats.

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
    /// Expects format: `arn:<partition>:<service>:<region>:<account>:<resource>`
    ///
    /// Validation rules:
    /// - Index 0 must be literal "arn"
    /// - Index 1 (partition) must be one of: aws, aws-cn, aws-us-gov (lowercased)
    /// - Index 2 (service) must not be empty (lowercased)
    /// - Index 3 (region) may be empty for global services (lowercased)
    /// - Index 4 (account) must be empty, "aws", or exactly 12 digits
    /// - Index 5 (resource) preserves case; all content after 5th colon is resource
    ///
    /// # Errors
    /// Returns an error if the ARN format is invalid.
    pub fn parse(s: &str) -> Result<Self, String> {
        let parts: Vec<&str> = s.splitn(6, ':').collect();

        if parts.len() < 6 {
            return Err(format!(
                "ARN must have 6 colon-separated parts, found {}",
                parts.len()
            ));
        }

        // Index 0: must be "arn"
        if parts[0] != "arn" {
            return Err(format!("ARN must start with 'arn:', got '{}'", parts[0]));
        }

        // Index 1: partition — must be one of aws, aws-cn, aws-us-gov
        let partition = parts[1].to_lowercase();
        if !["aws", "aws-cn", "aws-us-gov"].contains(&partition.as_str()) {
            return Err(format!(
                "Unknown partition '{}'; must be one of: aws, aws-cn, aws-us-gov",
                partition
            ));
        }

        // Index 2: service — must not be empty
        let service = parts[2].to_lowercase();
        if service.is_empty() {
            return Err("Service must not be empty".to_string());
        }

        // Index 3: region — may be empty (global services)
        let region = parts[3].to_lowercase();

        // Index 4: account — must be "", "aws", or exactly 12 digits
        let account = parts[4];
        if !account.is_empty() && account != "aws" {
            // Must be exactly 12 digits
            if account.len() != 12 {
                return Err(format!(
                    "Account must be empty, 'aws', or exactly 12 digits, got '{}'",
                    account
                ));
            }
            if !account.chars().all(|c| c.is_ascii_digit()) {
                return Err(format!(
                    "Account must contain only digits, got '{}'",
                    account
                ));
            }
        }

        // Index 5: resource — preserve case; splitn(6) captures everything after 5th colon
        let resource = parts[5];

        Ok(Self {
            partition,
            service,
            region,
            account: account.to_string(),
            resource: resource.to_string(),
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

/// Determines if a string is a valid node ID (parseable ARN without wildcards).
///
/// Returns `true` if:
/// - The string parses as a valid ARN
/// - The resource does not contain wildcard characters (`*` or `?`)
///
/// Returns `false` otherwise.
pub fn is_valid_node_id(s: &str) -> bool {
    match Arn::parse(s) {
        Ok(arn) => !arn.resource.contains('*') && !arn.resource.contains('?'),
        Err(_) => false,
    }
}

impl fmt::Display for Arn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.canonical())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arn_parse_comprehensive() {
        // Test cases: (input, should_parse, expected_fields_if_ok)
        let cases = vec![
            // Standard IAM user
            (
                "arn:aws:iam::123456789012:user/alice",
                true,
                ("aws", "iam", "", "123456789012", "user/alice"),
            ),
            // AWS-managed policy (account="aws")
            (
                "arn:aws:iam::aws:policy/AdministratorAccess",
                true,
                ("aws", "iam", "", "aws", "policy/AdministratorAccess"),
            ),
            // S3 bucket (no region, no account)
            (
                "arn:aws:s3:::my-bucket",
                true,
                ("aws", "s3", "", "", "my-bucket"),
            ),
            // STS assumed-role with embedded colons in resource
            (
                "arn:aws:sts::123456789012:assumed-role/Role/Session",
                true,
                (
                    "aws",
                    "sts",
                    "",
                    "123456789012",
                    "assumed-role/Role/Session",
                ),
            ),
            // IAM role with path
            (
                "arn:aws:iam::123456789012:role/path/to/role",
                true,
                ("aws", "iam", "", "123456789012", "role/path/to/role"),
            ),
            // China partition EC2
            (
                "arn:aws-cn:ec2:cn-north-1:123456789012:instance/i-abc",
                true,
                (
                    "aws-cn",
                    "ec2",
                    "cn-north-1",
                    "123456789012",
                    "instance/i-abc",
                ),
            ),
            // GovCloud partition
            (
                "arn:aws-us-gov:iam::123456789012:role/test",
                true,
                ("aws-us-gov", "iam", "", "123456789012", "role/test"),
            ),
            // Mixed-case service (should be normalized to lowercase)
            (
                "arn:aws:IAM::123456789012:user/alice",
                true,
                ("aws", "iam", "", "123456789012", "user/alice"),
            ),
        ];

        for (
            input,
            should_parse,
            (exp_partition, exp_service, exp_region, exp_account, exp_resource),
        ) in cases
        {
            if should_parse {
                let arn =
                    Arn::parse(input).expect(&format!("Expected parse to succeed for: {}", input));
                assert_eq!(
                    arn.partition, exp_partition,
                    "partition mismatch for: {}",
                    input
                );
                assert_eq!(arn.service, exp_service, "service mismatch for: {}", input);
                assert_eq!(arn.region, exp_region, "region mismatch for: {}", input);
                assert_eq!(arn.account, exp_account, "account mismatch for: {}", input);
                assert_eq!(
                    arn.resource, exp_resource,
                    "resource mismatch for: {}",
                    input
                );

                // Verify canonical round-trip for normalized form
                let canonical = arn.canonical();
                assert_eq!(
                    canonical,
                    format!(
                        "arn:{}:{}:{}:{}:{}",
                        exp_partition, exp_service, exp_region, exp_account, exp_resource
                    ),
                    "canonical mismatch for: {}",
                    input
                );
            }
        }
    }

    #[test]
    fn test_arn_parse_invalid() {
        let invalid_cases = vec![
            ("not-an-arn", "Non-ARN string"),
            (
                "arn:aws-fake:iam::123456789012:user/alice",
                "Unknown partition",
            ),
            (
                "arn:aws:iam::1234abcd5678:user/alice",
                "Account with letters",
            ),
            ("arn:aws:iam::12345:user/alice", "Account too short"),
            ("arn:aws::admin::role/test", "Empty service"),
            ("", "Empty string"),
            ("arn:aws:s3", "Too few parts"),
        ];

        for (input, reason) in invalid_cases {
            assert!(
                Arn::parse(input).is_err(),
                "Expected parse to fail for: {} ({})",
                input,
                reason
            );
        }
    }

    #[test]
    fn test_is_valid_node_id() {
        // Valid node IDs (parseable, no wildcards)
        let valid_inputs = vec![
            "arn:aws:iam::123456789012:user/alice",
            "arn:aws:iam::aws:policy/AdministratorAccess",
            "arn:aws:s3:::my-bucket",
            "arn:aws:sts::123456789012:assumed-role/Role/Session",
            "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
        ];

        for input in valid_inputs {
            assert!(
                is_valid_node_id(input),
                "Expected is_valid_node_id to return true for: {}",
                input
            );
        }

        // Invalid node IDs (wildcards or non-ARN)
        let invalid_inputs = vec![
            "arn:aws:s3:::*",                   // Wildcard in resource
            "arn:aws:iam::*:user/alice", // Wildcard in account (doesn't parse, but check behavior)
            "arn:aws:iam::123456789012:user/*", // Wildcard in resource
            "arn:aws:iam::123456789012:user/?", // Question mark in resource
            "not-an-arn",                // Non-ARN string
            "",                          // Empty string
        ];

        for input in invalid_inputs {
            assert!(
                !is_valid_node_id(input),
                "Expected is_valid_node_id to return false for: {}",
                input
            );
        }
    }

    #[test]
    fn test_arn_canonical_roundtrip() {
        let test_arns = vec![
            "arn:aws:iam::123456789012:user/alice",
            "arn:aws:s3:::bucket-name",
            "arn:aws:sts::123456789012:assumed-role/Role/Session",
            "arn:aws-cn:ec2:cn-north-1:123456789012:instance/i-abc",
        ];

        for original in test_arns {
            let arn = Arn::parse(original).expect(&format!("Failed to parse: {}", original));
            let canonical = arn.canonical();
            // Re-parse the canonical form to ensure it round-trips correctly
            let arn2 = Arn::parse(&canonical)
                .expect(&format!("Failed to re-parse canonical form: {}", canonical));
            assert_eq!(
                arn, arn2,
                "Round-trip failed for: {} -> {}",
                original, canonical
            );
        }
    }

    #[test]
    fn test_arn_resource_case_preservation() {
        // S3 bucket names are case-sensitive; verify we preserve case
        let arn = Arn::parse("arn:aws:s3:::MyBucket").expect("Failed to parse S3 ARN");
        assert_eq!(arn.resource, "MyBucket", "Resource case not preserved");

        let arn2 =
            Arn::parse("arn:aws:iam::123456789012:user/Alice").expect("Failed to parse IAM ARN");
        assert_eq!(arn2.resource, "user/Alice", "Resource case not preserved");
    }

    #[test]
    fn test_arn_display() {
        let arn = Arn::parse("arn:aws:iam::123456789012:user/alice").expect("Failed to parse");
        assert_eq!(
            arn.to_string(),
            "arn:aws:iam::123456789012:user/alice",
            "Display format mismatch"
        );
    }
}
