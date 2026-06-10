//! Integration tests for policy drift detection across version histories.

use activable_iam_engine::{
    analyze_version_history, compute_drift_score, diff_policies, parse_policy, DriftSeverity,
    PolicyVersion,
};

/// Test fixture: Real-world managed policy version history
/// Simulates AWS managed policy that was expanded over time
#[test]
fn test_real_world_policy_expansion_history() {
    // Version 1: Initial S3 read-only policy
    let policy_v1 = parse_policy(
        r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
        }]
    }"#,
    )
    .unwrap();

    // Version 2: Added PutObject (write permission)
    let policy_v2 = parse_policy(
        r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
            "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
        }]
    }"#,
    )
    .unwrap();

    // Version 3: Expanded to all S3 actions (dangerous)
    let policy_v3 = parse_policy(
        r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:*"],
            "Resource": ["*"]
        }]
    }"#,
    )
    .unwrap();

    let v1 = PolicyVersion {
        version_id: "v1".to_string(),
        policy_arn: "arn:aws:iam::123456789012:policy/S3ReadPolicy".to_string(),
        is_default: false,
        created_at: "2024-01-01T10:00:00Z".to_string(),
        policy: policy_v1,
    };

    let v2 = PolicyVersion {
        version_id: "v2".to_string(),
        policy_arn: "arn:aws:iam::123456789012:policy/S3ReadPolicy".to_string(),
        is_default: false,
        created_at: "2024-01-15T10:00:00Z".to_string(),
        policy: policy_v2,
    };

    let v3 = PolicyVersion {
        version_id: "v3".to_string(),
        policy_arn: "arn:aws:iam::123456789012:policy/S3ReadPolicy".to_string(),
        is_default: true,
        created_at: "2024-02-01T10:00:00Z".to_string(),
        policy: policy_v3,
    };

    // Analyze history (versions provided out of order)
    let diffs = analyze_version_history(&[v2.clone(), v1.clone(), v3.clone()]);

    // Should have 2 diffs
    assert_eq!(diffs.len(), 2);

    // First diff: v1 → v2 (PutObject added)
    let diff1 = &diffs[0];
    assert_eq!(diff1.from_version, "v1");
    assert_eq!(diff1.to_version, "v2");
    assert!(diff1.actions_added.contains(&"s3:PutObject".to_string()));
    assert_eq!(diff1.severity, DriftSeverity::Medium);

    // Second diff: v2 → v3 (s3:* expansion)
    let diff2 = &diffs[1];
    assert_eq!(diff2.from_version, "v2");
    assert_eq!(diff2.to_version, "v3");
    assert!(diff2.permission_expanded);
    // s3:* is not in the dangerous actions list, so it's Medium severity
    assert_eq!(diff2.severity, DriftSeverity::Medium);

    // Compute overall drift score
    let drift_score = compute_drift_score(&diffs);
    assert!(drift_score > 0.4); // Significant drift
    assert!(drift_score <= 1.0);
}

/// Test: Policy with dangerous IAM action expansion
#[test]
fn test_dangerous_iam_action_expansion() {
    let policy_initial = parse_policy(
        r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["ec2:DescribeInstances"],
            "Resource": "*"
        }]
    }"#,
    )
    .unwrap();

    let policy_dangerous = parse_policy(
        r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["ec2:DescribeInstances", "iam:CreatePolicyVersion", "iam:PutUserPolicy"],
            "Resource": "*"
        }]
    }"#,
    )
    .unwrap();

    let diff = diff_policies(
        &policy_initial,
        &policy_dangerous,
        "arn:aws:iam::123456789012:policy/Test",
        "v1",
        "v2",
    );

    assert_eq!(diff.severity, DriftSeverity::High);
    assert!(diff
        .actions_added
        .contains(&"iam:CreatePolicyVersion".to_string()));
    assert!(diff
        .actions_added
        .contains(&"iam:PutUserPolicy".to_string()));
    assert!(diff.permission_expanded);
}

/// Test: Multiple consecutive expansions → high drift score
#[test]
fn test_multiple_expansions_high_drift() {
    let versions = vec![
        PolicyVersion {
            version_id: "v1".to_string(),
            policy_arn: "arn:aws:iam::123456789012:policy/Test".to_string(),
            is_default: false,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            policy: parse_policy(
                r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#
            )
            .unwrap(),
        },
        PolicyVersion {
            version_id: "v2".to_string(),
            policy_arn: "arn:aws:iam::123456789012:policy/Test".to_string(),
            is_default: false,
            created_at: "2024-01-05T00:00:00Z".to_string(),
            policy: parse_policy(
                r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#
            )
            .unwrap(),
        },
        PolicyVersion {
            version_id: "v3".to_string(),
            policy_arn: "arn:aws:iam::123456789012:policy/Test".to_string(),
            is_default: false,
            created_at: "2024-01-10T00:00:00Z".to_string(),
            policy: parse_policy(
                r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#
            )
            .unwrap(),
        },
    ];

    let diffs = analyze_version_history(&versions);
    assert_eq!(diffs.len(), 2);

    let drift_score = compute_drift_score(&diffs);

    // All diffs are expansions with critical/high severity
    assert!(
        drift_score > 0.7,
        "Expected high drift score, got {}",
        drift_score
    );
    assert!(drift_score <= 1.0);
}

/// Test: Policy contraction (removal of permissions) → low/no drift
#[test]
fn test_policy_contraction_low_drift() {
    // Start with multiple actions on multiple resources
    let policy_broad = parse_policy(
        r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
            "Resource": ["arn:aws:s3:::bucket1/*", "arn:aws:s3:::bucket2/*"]
        }]
    }"#,
    )
    .unwrap();

    // Restrict to only GetObject on bucket1
    let policy_restricted = parse_policy(
        r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::bucket1/*"
        }]
    }"#,
    )
    .unwrap();

    let diff = diff_policies(
        &policy_broad,
        &policy_restricted,
        "arn:aws:iam::123456789012:policy/Test",
        "v1",
        "v2",
    );

    // When actions are removed and no new ones added, severity is Low
    assert_eq!(diff.severity, DriftSeverity::Low);
    assert!(!diff.permission_expanded);

    let drift_score = compute_drift_score(&[diff]);
    // One diff with no expansion → 0.0 drift
    assert_eq!(drift_score, 0.0);
}

/// Test: Real AWS managed policy pattern (AdministratorAccess simulation)
#[test]
fn test_admin_policy_pattern() {
    let policy_admin = parse_policy(
        r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }]
    }"#,
    )
    .unwrap();

    let v1 = PolicyVersion {
        version_id: "default".to_string(),
        policy_arn: "arn:aws:iam::123456789012:policy/AdministratorAccess".to_string(),
        is_default: true,
        created_at: "2024-01-01T00:00:00Z".to_string(),
        policy: policy_admin,
    };

    let diffs = analyze_version_history(&[v1]);

    // Single version → no diffs
    assert_eq!(diffs.len(), 0);
}

/// Test: Empty policies (no statements) → no drift
#[test]
fn test_empty_policy_no_drift() {
    let empty_policy = ParsedPolicy {
        version: "2012-10-17".to_string(),
        statements: vec![],
    };

    let diff = diff_policies(
        &empty_policy,
        &empty_policy,
        "arn:aws:iam::123456789012:policy/Empty",
        "v1",
        "v2",
    );

    assert_eq!(diff.severity, DriftSeverity::None);
    assert!(!diff.permission_expanded);

    let drift_score = compute_drift_score(&[diff]);
    assert_eq!(drift_score, 0.0);
}

// Re-import ParsedPolicy for direct construction if needed
use activable_iam_engine::ParsedPolicy;

/// Test: Complex multi-statement policy with mixed Allow/Deny
#[test]
fn test_complex_multi_statement_expansion() {
    let policy_before = parse_policy(
        r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowReadS3",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::my-bucket/*"
            },
            {
                "Sid": "DenyDeleteSecure",
                "Effect": "Deny",
                "Action": ["s3:DeleteObject"],
                "Resource": "arn:aws:s3:::my-bucket/secure/*"
            }
        ]
    }"#,
    )
    .unwrap();

    let policy_after = parse_policy(
        r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowReadWriteS3",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "arn:aws:s3:::my-bucket/*"
            },
            {
                "Sid": "DenyDeleteSecure",
                "Effect": "Deny",
                "Action": ["s3:DeleteObject"],
                "Resource": "arn:aws:s3:::my-bucket/secure/*"
            }
        ]
    }"#,
    )
    .unwrap();

    let diff = diff_policies(
        &policy_before,
        &policy_after,
        "arn:aws:iam::123456789012:policy/Complex",
        "v1",
        "v2",
    );

    // Only Allow statement changes should affect result
    assert!(diff.permission_expanded);
    assert!(diff.actions_added.contains(&"s3:PutObject".to_string()));
    assert_eq!(diff.severity, DriftSeverity::Medium);
}
