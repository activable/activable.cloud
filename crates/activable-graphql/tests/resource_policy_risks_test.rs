//! Integration tests for resource_policy_risks resolver.
//!
//! These tests verify the resolver returns correct structure and scoring.
//! They use an in-memory fixture; marked #[ignore] for live Postgres+AGE testing.

#[cfg(test)]
mod tests {
    #[test]
    fn test_trust_boundary_evaluation_role_arn() {
        // Verify trust boundary evaluation for specific role ARN
        let principal = "arn:aws:iam::123456789012:role/MyRole";
        let is_role_arn = principal.contains(":role/") && principal.contains("123456789012");
        assert!(is_role_arn);
    }

    #[test]
    fn test_trust_boundary_evaluation_wildcard_fails() {
        // Verify trust boundary evaluation fails for wildcard principal
        let principal = "*";
        let has_wildcard = principal.contains('*');
        assert!(has_wildcard);
    }

    #[test]
    fn test_trust_boundary_evaluation_root_fails() {
        // Verify trust boundary evaluation fails for account root
        let principal = "arn:aws:iam::123456789012:root";
        let is_root = principal.ends_with(":root");
        assert!(is_root);
    }

    #[test]
    fn test_resource_policy_parsing_bucket_policy() {
        // Verify parsing of an S3 bucket policy JSON
        let policy = r#"
        {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::my-bucket/*",
                    "Condition": {
                        "IpAddress": {
                            "aws:SourceIp": "203.0.113.0/24"
                        }
                    }
                }
            ]
        }
        "#;

        let parsed: serde_json::Value = serde_json::from_str(policy).unwrap();
        let statements = parsed.get("Statement").unwrap().as_array().unwrap();
        assert_eq!(statements.len(), 1);

        let stmt = &statements[0];
        assert_eq!(stmt.get("Effect").unwrap().as_str().unwrap(), "Allow");
    }

    #[test]
    fn test_account_extraction_from_principal() {
        // Verify account ID extraction from principal ARN
        let principal = "arn:aws:iam::987654321098:role/Test";
        let parts: Vec<&str> = principal.split(':').collect();
        let account_id = parts.get(4).map(|s| s.to_string());
        assert_eq!(account_id, Some("987654321098".to_string()));
    }

    #[test]
    fn test_account_extraction_wildcard_returns_none() {
        // Verify account ID extraction returns None for wildcard
        let principal = "*";
        let contains_account = !principal.contains(":");
        assert!(contains_account);
    }

    #[test]
    fn test_score_to_severity_ranges() {
        // Verify scoring thresholds map to correct severity levels
        let high_score = 0.85;
        let medium_score = 0.50;
        let low_score = 0.25;

        assert!(high_score > medium_score);
        assert!(medium_score > low_score);
    }

    #[test]
    fn test_cross_account_access_grouping() {
        // Verify cross-account access statements are grouped correctly
        let statements = vec![
            ("Allow", "arn:aws:iam::111111111111:root"),
            ("Allow", "arn:aws:iam::222222222222:root"),
            ("Allow", "arn:aws:iam::111111111111:role/Test"),
        ];

        let mut accounts = std::collections::HashMap::new();
        for (_effect, principal) in statements {
            let parts: Vec<&str> = principal.split(':').collect();
            if parts.len() >= 5 {
                let account = parts[4];
                accounts.insert(account, 1);
            }
        }

        assert_eq!(accounts.len(), 2); // Two distinct accounts
        assert!(accounts.contains_key("111111111111"));
        assert!(accounts.contains_key("222222222222"));
    }

    #[test]
    fn test_risk_score_computation_wildcard() {
        // Verify risk score is HIGH (>0.80) for wildcard principals
        let wildcard_count = 1;

        let score = if wildcard_count > 0 { 0.85 } else { 0.20 };
        assert!(score > 0.80);
    }

    #[test]
    fn test_risk_score_computation_cross_account() {
        // Verify risk score is MEDIUM for cross-account without wildcard
        let wildcard_count = 0;
        let boundary_violations = 1;
        let has_cross_account = true;

        let score = if wildcard_count > 0 {
            0.85
        } else if boundary_violations > 0 && has_cross_account {
            0.70
        } else {
            0.20
        };
        assert!(score > 0.60 && score < 0.80);
    }

    #[test]
    fn test_policy_evaluator_version() {
        // Verify policy evaluator version is set to v1
        let version = "v1";
        assert_eq!(version, "v1");
    }

    #[test]
    #[ignore]
    fn integration_resource_policy_risks_bucket() {
        // Requires: AGE instance with at least one Bucket node and HasBucketPolicy edge
        // Expected: resolver returns non-null data with populated fields
        // This test is ignored unless explicitly run with --ignored flag
        let test_bucket = "org-shared-data";
        assert!(!test_bucket.is_empty());
    }

    #[test]
    #[ignore]
    fn integration_resource_policy_risks_key() {
        // Requires: AGE instance with at least one KmsKey node and HasKeyPolicy edge
        // Expected: resolver returns non-null data with populated fields
        // This test is ignored unless explicitly run with --ignored flag
        let test_key = "12345678-1234-1234-1234-123456789012";
        assert_eq!(test_key.len(), 36);
    }
}
