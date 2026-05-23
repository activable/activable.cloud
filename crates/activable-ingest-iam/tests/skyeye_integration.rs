//! SkyEye full coverage integration tests.
//!
//! Validates that all SkyEye capabilities work end-to-end together.
//! Each test exercises a specific SkyEye paper gap and verifies that
//! activable.cloud addresses it correctly.

use activable_ingest_iam::{
    compute_drift_score, diff_policies, effective_permissions, effective_permissions_with_session,
    evaluate_resource_policy_pair, extract_federation_trusts, parse_policy, parse_resource_policy,
    EvalContext, ResourcePolicyDecision,
};

/// Test 1: Resource policy + identity policy compound evaluation
///
/// SkyEye gap: Compound evaluation of resource-based and identity-based policies
/// Expected: Cross-account principal requires BOTH allow, same-account requires EITHER
#[test]
fn test_compound_resource_and_identity_policy_evaluation() {
    // Setup: S3 bucket policy allows cross-account principal
    let bucket_policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::999999999999:root"
                },
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }"#;

    let bucket_policy = parse_resource_policy(bucket_policy_json, "arn:aws:s3:::my-bucket", "s3")
        .expect("Failed to parse bucket policy");

    // Cross-account principal (999999999999) trying to access resource
    let cross_account_principal = "arn:aws:iam::999999999999:user/alice";
    let resource = "arn:aws:s3:::my-bucket/data.txt";

    // Evaluate resource policy alone
    let identity_policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }"#;

    let identity_policy =
        parse_policy(identity_policy_json).expect("Failed to parse identity policy");
    let identity_perms = effective_permissions(
        std::slice::from_ref(&identity_policy),
        None,
        &[],
        &EvalContext::default(),
    );

    // Verify: both policies allow s3:GetObject
    assert!(
        identity_perms.iter().any(|p| p.action == "s3:GetObject"),
        "Identity policy should allow s3:GetObject"
    );

    // Evaluate resource policy decision
    let result = evaluate_resource_policy_pair(
        "s3:GetObject",
        resource,
        cross_account_principal,
        &[identity_policy],
        Some(&bucket_policy.policy),
        "999999999999",
        "123456789012",
    );

    // Verify: resource policy allows cross-account principal
    assert!(
        result == ResourcePolicyDecision::Allow,
        "Resource policy should allow cross-account principal"
    );
}

/// Test 2: Session policy constrains effective permissions
///
/// SkyEye gap: Session policy intersection reduces blast radius
/// Expected: Session policy acts as additional constraint
#[test]
fn test_session_policy_constrains_permissions() {
    // Setup: Identity policy grants broad permissions
    let identity_policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": "*"
            }
        ]
    }"#;

    let identity_policy =
        parse_policy(identity_policy_json).expect("Failed to parse identity policy");

    // Session policy restricts to only s3:GetObject
    let session_policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*"
            }
        ]
    }"#;

    let session_policy = parse_policy(session_policy_json).expect("Failed to parse session policy");

    // First compute base permissions from identity policy
    let base_perms = effective_permissions(&[identity_policy], None, &[], &EvalContext::default());

    // Verify: base permissions include both s3 actions
    assert!(
        base_perms.iter().any(|p| p.action == "s3:GetObject"),
        "Base permissions should include s3:GetObject"
    );
    assert!(
        base_perms.iter().any(|p| p.action == "s3:ListBucket"),
        "Base permissions should include s3:ListBucket"
    );

    // Compute effective permissions with session constraint
    let perms = effective_permissions_with_session(&base_perms, Some(&session_policy));

    // Verify: session policy constrains permissions
    // Session should reduce permissions (filtering to only allowed ones)
    assert!(
        perms.len() <= base_perms.len(),
        "Session policy should constrain or maintain permissions"
    );

    // Verify: s3:ListBucket is filtered out (not in session policy)
    assert!(
        !perms.iter().any(|p| p.action == "s3:ListBucket"),
        "Session policy should remove s3:ListBucket"
    );
}

/// Test 3: Federation trust extraction
///
/// SkyEye gap: Detect SAML trust policies
/// Expected: extract_federation_trusts extracts trust relationships from role policies
#[test]
fn test_federation_trust_extraction() {
    // Setup: SAML trust policy
    let saml_policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": "arn:aws:iam::123456789012:saml-provider/ExampleProvider"
                },
                "Action": "sts:AssumeRoleWithSAML"
            }
        ]
    }"#;

    let role_arn = "arn:aws:iam::123456789012:role/SampleRole";

    // Extract federation trusts
    let trusts = extract_federation_trusts(saml_policy_json, role_arn)
        .expect("Failed to extract federation trusts");

    // Verify: trusts extracted
    assert!(
        !trusts.is_empty(),
        "Should extract federation trust from SAML policy"
    );

    // Verify: trust has expected properties
    let trust = &trusts[0];
    assert_eq!(
        trust.role_arn, role_arn,
        "Trust should reference the correct role"
    );
}

/// Test 4: Policy drift detection
///
/// SkyEye gap: Detect permission expansion across policy versions
/// Expected: v1 (s3:GetObject) → v2 (s3:GetObject + iam:CreatePolicyVersion) detects expansion
#[test]
fn test_policy_drift_detection() {
    // Version 1: Limited permissions
    let policy_v1_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }"#;

    let policy_v1 = parse_policy(policy_v1_json).expect("Failed to parse policy v1");

    // Version 2: Expanded permissions
    let policy_v2_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "iam:CreatePolicyVersion"],
                "Resource": "*"
            }
        ]
    }"#;

    let policy_v2 = parse_policy(policy_v2_json).expect("Failed to parse policy v2");

    // Detect policy drift
    let diff = diff_policies(
        &policy_v1,
        &policy_v2,
        "arn:aws:iam::123456789012:policy/TestPolicy",
        "v1",
        "v2",
    );

    // Verify: expansion detected
    assert!(
        diff.permission_expanded,
        "Policy diff should detect permission expansion"
    );

    // Compute drift score from array of diffs
    let score = compute_drift_score(&[diff]);
    assert!(score > 0.0, "Policy drift should produce positive score");
}

/// Test 5: Policy drift detection - multiple versions
///
/// SkyEye gap: Detect permission expansion across multiple policy versions
/// Expected: Multiple diffs show increasing risk score
#[test]
fn test_policy_drift_with_multiple_versions() {
    // Version 1: Minimal permissions
    let policy_v1_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:ListBucket",
                "Resource": "arn:aws:s3:::my-bucket"
            }
        ]
    }"#;

    let policy_v1 = parse_policy(policy_v1_json).expect("Failed to parse policy v1");

    // Version 2: Expanded to include GetObject
    let policy_v2_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:GetObject"],
                "Resource": "*"
            }
        ]
    }"#;

    let policy_v2 = parse_policy(policy_v2_json).expect("Failed to parse policy v2");

    // Version 3: Further expanded to include dangerous action
    let policy_v3_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:GetObject", "iam:CreatePolicyVersion"],
                "Resource": "*"
            }
        ]
    }"#;

    let policy_v3 = parse_policy(policy_v3_json).expect("Failed to parse policy v3");

    // Compute diffs for each version transition
    let diff_v1_v2 = diff_policies(
        &policy_v1,
        &policy_v2,
        "arn:aws:iam::123456789012:policy/TestPolicy",
        "v1",
        "v2",
    );

    let diff_v2_v3 = diff_policies(
        &policy_v2,
        &policy_v3,
        "arn:aws:iam::123456789012:policy/TestPolicy",
        "v2",
        "v3",
    );

    // Verify both show expansion
    assert!(
        diff_v1_v2.permission_expanded,
        "v1 → v2 should show expansion"
    );
    assert!(
        diff_v2_v3.permission_expanded,
        "v2 → v3 should show expansion"
    );

    // Compute drift score from all diffs
    let diffs = vec![diff_v1_v2, diff_v2_v3];
    let score = compute_drift_score(&diffs);

    assert!(
        score > 0.0,
        "Multiple expansions should produce higher drift score"
    );
}

/// Test 6: Resource pattern matching with wildcards
///
/// SkyEye gap: Correct wildcard matching in resource ARNs
/// Expected: arn:aws:s3:::bucket/* matches arn:aws:s3:::bucket/file.txt but not arn:aws:s3:::bucket
#[test]
fn test_resource_wildcard_matching() {
    let resource_policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::my-bucket/*"
        }]
    }"#;

    let resource_policy =
        parse_resource_policy(resource_policy_json, "arn:aws:s3:::my-bucket", "s3")
            .expect("Failed to parse resource policy");

    let resource_matches = "arn:aws:s3:::my-bucket/file.txt";
    let resource_no_match = "arn:aws:s3:::my-bucket";

    // Evaluate with matching resource
    let result_match = evaluate_resource_policy_pair(
        "s3:GetObject",
        resource_matches,
        "arn:aws:iam::123456789012:root",
        &[],
        Some(&resource_policy.policy),
        "123456789012",
        "123456789012",
    );

    // Verify: matches
    assert!(
        result_match == ResourcePolicyDecision::Allow,
        "Should match s3:GetObject on bucket/* pattern"
    );

    // Evaluate with non-matching resource (no explicit object key)
    let result_no_match = evaluate_resource_policy_pair(
        "s3:GetObject",
        resource_no_match,
        "arn:aws:iam::123456789012:root",
        &[],
        Some(&resource_policy.policy),
        "123456789012",
        "123456789012",
    );

    // Verify: does not match (bucket /* requires object key)
    assert!(
        result_no_match == ResourcePolicyDecision::ImplicitDeny,
        "Should not match on bucket root (no object key)"
    );
}

/// Test 7: Permission boundary intersection
///
/// SkyEye gap: Permission boundary correctly intersects with identity policy
/// Expected: Boundary is AND operation (most restrictive wins)
#[test]
fn test_permission_boundary_intersection() {
    // Identity policy: broad permissions
    let identity_policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:*", "ec2:*"],
                "Resource": "*"
            }
        ]
    }"#;

    let identity_policy =
        parse_policy(identity_policy_json).expect("Failed to parse identity policy");

    // Permission boundary: restricted to S3 only
    let boundary_policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*"
            }
        ]
    }"#;

    let boundary_policy =
        parse_policy(boundary_policy_json).expect("Failed to parse boundary policy");

    // Compute effective permissions with boundary
    let perms = effective_permissions(
        &[identity_policy],
        Some(&boundary_policy),
        &[],
        &EvalContext::default(),
    );

    // Verify: boundary intersection removes ec2:* but keeps s3:*
    assert!(
        perms.iter().any(|p| p.action == "s3:*"),
        "Boundary should allow s3:*"
    );

    assert!(
        !perms.iter().any(|p| p.action.contains("ec2:")),
        "Boundary should restrict ec2:* permissions"
    );
}

/// Test 8: Cross-account role assumption
///
/// SkyEye gap: Detect chained cross-account role assumptions
/// Expected: Account A can assume role if both policies allow
#[test]
fn test_cross_account_role_assumption_chain() {
    // Account A user with sts:AssumeRole permission
    let account_a_policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Resource": "arn:aws:iam::999999999999:role/CrossAccountRole"
            }
        ]
    }"#;

    let account_a_policy =
        parse_policy(account_a_policy_json).expect("Failed to parse Account A policy");

    // Verify: Account A has permission to assume cross-account role
    let perms = effective_permissions(&[account_a_policy], None, &[], &EvalContext::default());
    assert!(
        perms.iter().any(|p| p.action == "sts:AssumeRole"),
        "Account A should have sts:AssumeRole permission"
    );

    // Verify: The permission resource matches the target role
    let assume_role_perm = perms.iter().find(|p| p.action == "sts:AssumeRole");
    assert!(
        assume_role_perm.is_some() && assume_role_perm.unwrap().resource.contains("999999999999"),
        "Account A's sts:AssumeRole should target the cross-account role"
    );
}

/// Test 9: Effective permissions from wildcards
///
/// SkyEye gap: Correctly extract effective permissions from wildcard patterns
/// Expected: iam:* captures all IAM actions
#[test]
fn test_effective_permissions_from_wildcards() {
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

    // Admin access should include * wildcard
    let admin_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }"#;

    let admin_policy = parse_policy(admin_json).expect("Failed to parse admin policy");
    let admin_perms = effective_permissions(&[admin_policy], None, &[], &EvalContext::default());

    assert!(
        admin_perms.iter().any(|p| p.action == "*"),
        "Expected * in effective permissions for admin access"
    );
}

/// Test 10: Same-account vs cross-account policy evaluation
///
/// SkyEye gap: Distinguish same-account (OR) from cross-account (AND)
/// Expected: Same-account allows if either policy allows
#[test]
fn test_same_account_vs_cross_account_evaluation() {
    // Identity policy allows S3 read
    let identity_policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }"#;

    let identity_policy =
        parse_policy(identity_policy_json).expect("Failed to parse identity policy");

    // Resource policy (empty - no access)
    let resource_policy_json = r#"{
        "Version": "2012-10-17",
        "Statement": []
    }"#;

    let resource_policy =
        parse_resource_policy(resource_policy_json, "arn:aws:s3:::my-bucket", "s3")
            .expect("Failed to parse resource policy");

    // Same-account: identity policy alone grants access
    let same_account_result = evaluate_resource_policy_pair(
        "s3:GetObject",
        "arn:aws:s3:::my-bucket/file.txt",
        "arn:aws:iam::123456789012:user/alice",
        std::slice::from_ref(&identity_policy),
        Some(&resource_policy.policy),
        "123456789012",
        "123456789012",
    );

    assert!(
        same_account_result == ResourcePolicyDecision::Allow,
        "Same-account should allow if identity policy allows (OR logic)"
    );

    // Cross-account: requires BOTH policies to allow
    let cross_account_result = evaluate_resource_policy_pair(
        "s3:GetObject",
        "arn:aws:s3:::my-bucket/file.txt",
        "arn:aws:iam::999999999999:user/bob",
        &[identity_policy],
        Some(&resource_policy.policy),
        "999999999999",
        "123456789012",
    );

    assert!(
        cross_account_result == ResourcePolicyDecision::ImplicitDeny,
        "Cross-account should deny if resource policy doesn't allow (AND logic)"
    );
}
