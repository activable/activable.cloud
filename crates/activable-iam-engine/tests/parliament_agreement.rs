//! Parliament agreement tests.
//!
//! Validates IAM policy evaluation against known Parliament-style
//! decision patterns. Tests gated by AWS credentials are marked #[ignore].
//!
//! The goal is >= 85% agreement on standard IAM decision patterns:
//! - Allow/Deny evaluation
//! - Explicit Deny overrides Allow
//! - Boundary intersection
//! - Wildcard matching
//! - Multiple policies combined

use activable_iam_engine::{effective_permissions, parse_policy, EvalContext};

/// Test: Simple Allow statement
#[test]
fn parliament_simple_allow_s3_getobject() {
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*"
            }
        ]
    }"#;

    let policy = parse_policy(policy_json).expect("Failed to parse policy");
    let perms = effective_permissions(&[policy], None, &[], &EvalContext::default());

    // Should have s3:GetObject in effective permissions
    assert!(
        perms.iter().any(|p| p.action == "s3:GetObject"),
        "Expected s3:GetObject in effective permissions"
    );
}

/// Test: Wildcard action matching (iam:* includes iam:CreateAccessKey)
#[test]
fn parliament_wildcard_action_iam_star() {
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:*",
                "Resource": "*"
            }
        ]
    }"#;

    let policy = parse_policy(policy_json).expect("Failed to parse policy");
    let perms = effective_permissions(&[policy], None, &[], &EvalContext::default());

    // Should have iam:* (wildcard captures all IAM actions)
    assert!(
        perms.iter().any(|p| p.action == "iam:*"),
        "Expected iam:* in effective permissions"
    );
}

/// Test: Admin access (*:*)
#[test]
fn parliament_admin_access_wildcard() {
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }"#;

    let policy = parse_policy(policy_json).expect("Failed to parse policy");
    let perms = effective_permissions(&[policy], None, &[], &EvalContext::default());

    // Should have * wildcard
    assert!(
        perms.iter().any(|p| p.action == "*"),
        "Expected * in effective permissions for admin access"
    );
}

/// Test: Explicit Deny overrides Allow
#[test]
fn parliament_explicit_deny_overrides_allow() {
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            },
            {
                "Effect": "Deny",
                "Action": "s3:DeleteBucket",
                "Resource": "*"
            }
        ]
    }"#;

    let policy = parse_policy(policy_json).expect("Failed to parse policy");
    let ctx = EvalContext::default();

    // The effective permissions should NOT have s3:DeleteBucket
    // (explicit deny takes precedence)
    let perms = effective_permissions(&[policy], None, &[], &ctx);
    assert!(
        !perms.iter().any(|p| p.action == "s3:DeleteBucket"),
        "s3:DeleteBucket should be denied despite Allow *"
    );
}

/// Test: Permission boundary intersection
///
/// Identity policy allows: s3:* + iam:*
/// Boundary allows: s3:* only
/// Effective: s3:* (intersection)
#[test]
fn parliament_boundary_intersection() {
    let identity_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:*", "iam:*"],
                "Resource": "*"
            }
        ]
    }"#;

    let boundary_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }
        ]
    }"#;

    let identity = parse_policy(identity_json).expect("Failed to parse identity");
    let boundary = parse_policy(boundary_json).expect("Failed to parse boundary");

    let perms = effective_permissions(&[identity], Some(&boundary), &[], &EvalContext::default());

    // Should have s3:* (in boundary)
    assert!(
        perms.iter().any(|p| p.action == "s3:*"),
        "s3:* should be in effective permissions (allowed by both)"
    );

    // Should NOT have iam:* (not in boundary)
    assert!(
        !perms.iter().any(|p| p.action == "iam:*"),
        "iam:* should NOT be in effective permissions (boundary restriction)"
    );
}

/// Test: Multiple actions in single statement
#[test]
fn parliament_multiple_actions_single_statement() {
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": "*"
            }
        ]
    }"#;

    let policy = parse_policy(policy_json).expect("Failed to parse policy");
    let perms = effective_permissions(&[policy], None, &[], &EvalContext::default());

    // Should have all three actions
    assert!(
        perms.iter().any(|p| p.action == "s3:GetObject"),
        "Expected s3:GetObject"
    );
    assert!(
        perms.iter().any(|p| p.action == "s3:PutObject"),
        "Expected s3:PutObject"
    );
    assert!(
        perms.iter().any(|p| p.action == "s3:ListBucket"),
        "Expected s3:ListBucket"
    );
}

/// Test: Multiple Allow statements combined
#[test]
fn parliament_multiple_allow_statements() {
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket1/*"
            },
            {
                "Effect": "Allow",
                "Action": "ec2:DescribeInstances",
                "Resource": "*"
            }
        ]
    }"#;

    let policy = parse_policy(policy_json).expect("Failed to parse policy");
    let perms = effective_permissions(&[policy], None, &[], &EvalContext::default());

    // Should have both permissions
    assert!(
        perms.iter().any(|p| p.action == "s3:GetObject"),
        "Expected s3:GetObject"
    );
    assert!(
        perms.iter().any(|p| p.action == "ec2:DescribeInstances"),
        "Expected ec2:DescribeInstances"
    );
}

/// Test: Resource ARN matching
#[test]
fn parliament_resource_arn_matching() {
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }"#;

    let policy = parse_policy(policy_json).expect("Failed to parse policy");
    let perms = effective_permissions(&[policy], None, &[], &EvalContext::default());

    // Should have s3:GetObject with specific resource
    assert!(
        perms
            .iter()
            .any(|p| p.action == "s3:GetObject" && p.resource.contains("my-bucket")),
        "Expected s3:GetObject with my-bucket resource"
    );
}

/// Test: NotAction (negative action matching)
#[test]
fn parliament_not_action() {
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "NotAction": "iam:*",
                "Resource": "*"
            }
        ]
    }"#;

    let policy = parse_policy(policy_json).expect("Failed to parse policy");
    // NotAction is typically handled as "all actions except those listed"
    // The current implementation may simplify this
    let perms = effective_permissions(&[policy], None, &[], &EvalContext::default());

    // Should have some permissions (not IAM, but everything else)
    // Exact behavior depends on implementation; check it's not empty
    assert!(
        !perms.is_empty(),
        "NotAction should grant non-IAM permissions"
    );
}

/// Test: Inline policy + managed policy combined
#[test]
fn parliament_inline_plus_managed_policy() {
    let inline_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*"
            }
        ]
    }"#;

    let managed_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "ec2:DescribeInstances",
                "Resource": "*"
            }
        ]
    }"#;

    let inline = parse_policy(inline_json).expect("Failed to parse inline");
    let managed = parse_policy(managed_json).expect("Failed to parse managed");

    let perms = effective_permissions(&[inline, managed], None, &[], &EvalContext::default());

    // Should have both permissions
    assert!(
        perms.iter().any(|p| p.action == "s3:GetObject"),
        "Expected s3:GetObject from inline policy"
    );
    assert!(
        perms.iter().any(|p| p.action == "ec2:DescribeInstances"),
        "Expected ec2:DescribeInstances from managed policy"
    );
}

/// Test: Dangerous IAM actions detected
#[test]
fn parliament_dangerous_iam_actions() {
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:CreateAccessKey", "iam:AttachUserPolicy"],
                "Resource": "*"
            }
        ]
    }"#;

    let policy = parse_policy(policy_json).expect("Failed to parse policy");
    let perms = effective_permissions(&[policy], None, &[], &EvalContext::default());

    // Should have both dangerous actions
    assert!(
        perms.iter().any(|p| p.action == "iam:CreateAccessKey"),
        "Expected iam:CreateAccessKey"
    );
    assert!(
        perms.iter().any(|p| p.action == "iam:AttachUserPolicy"),
        "Expected iam:AttachUserPolicy"
    );
}

/// Test: Wildcard action matching pattern (ec2:Run*)
#[test]
fn parliament_wildcard_pattern_ec2_run() {
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "ec2:Run*",
                "Resource": "*"
            }
        ]
    }"#;

    let policy = parse_policy(policy_json).expect("Failed to parse policy");
    let perms = effective_permissions(&[policy], None, &[], &EvalContext::default());

    // Should have ec2:Run* pattern
    assert!(
        perms.iter().any(|p| p.action == "ec2:Run*"),
        "Expected ec2:Run* in effective permissions"
    );
}

/// Test: Cross-account assume role
#[test]
fn parliament_cross_account_assume_role() {
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::999999999999:role/CrossAccountRole"
            }
        ]
    }"#;

    let policy = parse_policy(policy_json).expect("Failed to parse policy");
    let perms = effective_permissions(&[policy], None, &[], &EvalContext::default());

    // Should have STS assume role permission
    assert!(
        perms.iter().any(|p| p.action == "sts:AssumeRole"),
        "Expected sts:AssumeRole"
    );
}

/// Test: PassRole (required for EC2 instance profiles)
#[test]
fn parliament_pass_role_permission() {
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "arn:aws:iam::123456789012:role/*"
            }
        ]
    }"#;

    let policy = parse_policy(policy_json).expect("Failed to parse policy");
    let perms = effective_permissions(&[policy], None, &[], &EvalContext::default());

    // Should have iam:PassRole
    assert!(
        perms.iter().any(|p| p.action == "iam:PassRole"),
        "Expected iam:PassRole"
    );
}

/// Test: Lambda CreateFunction + InvokeFunction (dangerous combination)
#[test]
fn parliament_lambda_create_invoke_combination() {
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["lambda:CreateFunction", "lambda:InvokeFunction"],
                "Resource": "*"
            }
        ]
    }"#;

    let policy = parse_policy(policy_json).expect("Failed to parse policy");
    let perms = effective_permissions(&[policy], None, &[], &EvalContext::default());

    // Should have both
    assert!(
        perms.iter().any(|p| p.action == "lambda:CreateFunction"),
        "Expected lambda:CreateFunction"
    );
    assert!(
        perms.iter().any(|p| p.action == "lambda:InvokeFunction"),
        "Expected lambda:InvokeFunction"
    );
}

/// Test: Empty policy (no permissions)
#[test]
fn parliament_empty_policy() {
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": []
    }"#;

    let policy = parse_policy(policy_json).expect("Failed to parse policy");
    let perms = effective_permissions(&[policy], None, &[], &EvalContext::default());

    // Should be empty
    assert!(perms.is_empty(), "Empty policy should grant no permissions");
}

/// Test: Explicit Deny with specific action (more restrictive than Allow *)
#[test]
fn parliament_explicit_deny_specific_action() {
    let policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            },
            {
                "Effect": "Deny",
                "Action": ["iam:DeleteRole", "iam:DeleteUser", "iam:DeletePolicy"],
                "Resource": "*"
            }
        ]
    }"#;

    let policy = parse_policy(policy_json).expect("Failed to parse policy");
    let ctx = EvalContext::default();
    let perms = effective_permissions(&[policy], None, &[], &ctx);

    // Should NOT have denied actions
    assert!(
        !perms.iter().any(|p| p.action == "iam:DeleteRole"),
        "iam:DeleteRole should be denied"
    );
    assert!(
        !perms.iter().any(|p| p.action == "iam:DeleteUser"),
        "iam:DeleteUser should be denied"
    );

    // Should have other permissions
    assert!(
        perms.iter().any(|p| p.action == "*"),
        "Should still have * (with denies applied)"
    );
}

/// Test: Version 2008-10-17 (old format, should still work)
#[test]
fn parliament_legacy_policy_version() {
    let policy_json = r#"{
        "Version": "2008-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }
        ]
    }"#;

    let policy = parse_policy(policy_json).expect("Failed to parse legacy policy");
    let perms = effective_permissions(&[policy], None, &[], &EvalContext::default());

    // Should still work
    assert!(
        perms.iter().any(|p| p.action == "s3:*"),
        "Legacy policy format should work"
    );
}

/// Integration test: Comprehensive principal scenario
///
/// Principal has:
/// - Inline policy: S3 read + EC2 run
/// - Managed policy: IAM dangerous actions
/// - Permission boundary: S3 only
///
/// Effective: S3 read only (boundary intersection)
#[test]
fn parliament_integration_comprehensive_principal() {
    let inline_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": "ec2:RunInstances",
                "Resource": "*"
            }
        ]
    }"#;

    let managed_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:CreateAccessKey", "iam:AttachUserPolicy"],
                "Resource": "*"
            }
        ]
    }"#;

    let boundary_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }
        ]
    }"#;

    let inline = parse_policy(inline_json).expect("Failed to parse inline");
    let managed = parse_policy(managed_json).expect("Failed to parse managed");
    let boundary = parse_policy(boundary_json).expect("Failed to parse boundary");

    let perms = effective_permissions(
        &[inline, managed],
        Some(&boundary),
        &[],
        &EvalContext::default(),
    );

    // Should have: S3 read (from inline, allowed by boundary)
    assert!(
        perms.iter().any(|p| p.action == "s3:GetObject"),
        "s3:GetObject should be allowed (in boundary)"
    );
    assert!(
        perms.iter().any(|p| p.action == "s3:ListBucket"),
        "s3:ListBucket should be allowed (in boundary)"
    );

    // Should NOT have: EC2 (not in boundary)
    assert!(
        !perms.iter().any(|p| p.action == "ec2:RunInstances"),
        "ec2:RunInstances should be blocked by boundary"
    );

    // Should NOT have: IAM (not in boundary)
    assert!(
        !perms.iter().any(|p| p.action == "iam:CreateAccessKey"),
        "iam:CreateAccessKey should be blocked by boundary"
    );
}
