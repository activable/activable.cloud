//! Integration tests for Phase 3: Deny engine + boundary evaluation
#![cfg(test)]

use crate::boundary_evaluator::{boundary_allows, evaluate_with_boundary, BoundaryResult};
use crate::condition_evaluator::evaluate_condition;
use crate::deny_engine::{evaluate_deny, evaluate_deny_with_context, EvalResult};
use crate::eval_context::EvalContext;
use crate::scp_evaluator::scp_allows;
use crate::types::{ActionPattern, Condition, Effect, PolicyStatement, ResourcePattern};

// Helper to create a simple statement
fn stmt(effect: Effect, actions: &[&str], resources: &[&str]) -> PolicyStatement {
    PolicyStatement {
        sid: None,
        effect,
        actions: actions
            .iter()
            .map(|a| ActionPattern(a.to_string()))
            .collect(),
        not_actions: vec![],
        resources: resources
            .iter()
            .map(|r| ResourcePattern(r.to_string()))
            .collect(),
        not_resources: vec![],
        conditions: vec![],
    }
}

// Helper to create a statement with NotAction
fn stmt_with_not_action(
    effect: Effect,
    not_actions: &[&str],
    resources: &[&str],
) -> PolicyStatement {
    PolicyStatement {
        sid: None,
        effect,
        actions: vec![],
        not_actions: not_actions
            .iter()
            .map(|a| ActionPattern(a.to_string()))
            .collect(),
        resources: resources
            .iter()
            .map(|r| ResourcePattern(r.to_string()))
            .collect(),
        not_resources: vec![],
        conditions: vec![],
    }
}

// Helper to create a condition
fn condition(operator: &str, key: &str, values: &[&str]) -> Condition {
    Condition {
        operator: operator.to_string(),
        key: key.to_string(),
        values: values.iter().map(|v| v.to_string()).collect(),
    }
}

// ============================================================================
// Test group 1: Explicit Deny overrides Allow
// ============================================================================

#[test]
fn deny_overrides_allow_same_action() {
    let statements = vec![
        stmt(Effect::Allow, &["s3:*"], &["*"]),
        stmt(Effect::Deny, &["s3:DeleteBucket"], &["*"]),
    ];
    let result = evaluate_deny(&statements, "s3:DeleteBucket", "arn:aws:s3:::my-bucket");
    assert_eq!(result, EvalResult::ExplicitDeny);
}

#[test]
fn allow_when_no_deny_matches() {
    let statements = vec![
        stmt(Effect::Allow, &["s3:*"], &["*"]),
        stmt(Effect::Deny, &["iam:*"], &["*"]),
    ];
    let result = evaluate_deny(&statements, "s3:GetObject", "arn:aws:s3:::bucket/key");
    assert_eq!(result, EvalResult::NoExplicitDeny);
}

#[test]
fn deny_with_not_action_blocks_unlisted_actions() {
    // NotAction: ["iam:ChangePassword"] means deny ALL actions EXCEPT ChangePassword
    let stmt_deny = stmt_with_not_action(Effect::Deny, &["iam:ChangePassword"], &["*"]);
    let result = evaluate_deny(&[stmt_deny], "s3:GetObject", "*");
    assert_eq!(result, EvalResult::ExplicitDeny); // s3:GetObject is NOT in the NotAction list → denied
}

#[test]
fn deny_with_not_action_allows_listed_actions() {
    let stmt_deny = stmt_with_not_action(Effect::Deny, &["iam:ChangePassword"], &["*"]);
    let result = evaluate_deny(&[stmt_deny], "iam:ChangePassword", "*");
    assert_eq!(result, EvalResult::NoExplicitDeny); // ChangePassword IS in NotAction → NOT denied
}

#[test]
fn deny_with_resource_pattern() {
    let stmt_deny = stmt(Effect::Deny, &["s3:*"], &["arn:aws:s3:::secret-*"]);
    let result1 = evaluate_deny(
        &[stmt_deny.clone()],
        "s3:GetObject",
        "arn:aws:s3:::secret-data",
    );
    assert_eq!(result1, EvalResult::ExplicitDeny);

    let result2 = evaluate_deny(&[stmt_deny], "s3:GetObject", "arn:aws:s3:::public-data");
    assert_eq!(result2, EvalResult::NoExplicitDeny);
}

// ============================================================================
// Test group 2: Deny with conditions
// ============================================================================

#[test]
fn deny_with_matching_condition() {
    let mut deny = stmt(Effect::Deny, &["s3:*"], &["*"]);
    deny.conditions.push(condition(
        "StringNotEquals",
        "aws:RequestedRegion",
        &["us-east-1"],
    ));
    let context = EvalContext {
        region: "eu-west-1".to_string(),
        ..Default::default()
    };
    let result = evaluate_deny_with_context(&[deny], "s3:GetObject", "*", &context);
    assert_eq!(result, EvalResult::ExplicitDeny); // condition matches → deny fires
}

#[test]
fn deny_with_non_matching_condition_does_not_fire() {
    let mut deny = stmt(Effect::Deny, &["s3:*"], &["*"]);
    deny.conditions.push(condition(
        "StringNotEquals",
        "aws:RequestedRegion",
        &["us-east-1"],
    ));
    let context = EvalContext {
        region: "us-east-1".to_string(),
        ..Default::default()
    };
    let result = evaluate_deny_with_context(&[deny], "s3:GetObject", "*", &context);
    assert_eq!(result, EvalResult::NoExplicitDeny); // region IS us-east-1, so StringNotEquals = false
}

#[test]
fn deny_with_multiple_conditions_all_must_match() {
    let mut deny = stmt(Effect::Deny, &["s3:*"], &["*"]);
    deny.conditions.push(condition(
        "StringEquals",
        "aws:RequestedRegion",
        &["us-east-1"],
    ));
    deny.conditions
        .push(condition("Bool", "aws:SecureTransport", &["true"]));
    let context = EvalContext {
        region: "us-east-1".to_string(),
        secure_transport: true,
        ..Default::default()
    };
    let result = evaluate_deny_with_context(&[deny], "s3:GetObject", "*", &context);
    assert_eq!(result, EvalResult::ExplicitDeny); // both conditions match
}

#[test]
fn deny_with_partial_matching_conditions_does_not_fire() {
    let mut deny = stmt(Effect::Deny, &["s3:*"], &["*"]);
    deny.conditions.push(condition(
        "StringEquals",
        "aws:RequestedRegion",
        &["us-east-1"],
    ));
    deny.conditions
        .push(condition("Bool", "aws:SecureTransport", &["true"]));
    let context = EvalContext {
        region: "us-east-1".to_string(),
        secure_transport: false, // does NOT match
        ..Default::default()
    };
    let result = evaluate_deny_with_context(&[deny], "s3:GetObject", "*", &context);
    assert_eq!(result, EvalResult::NoExplicitDeny); // not all conditions match
}

// ============================================================================
// Test group 3: Permission boundary intersection
// ============================================================================

#[test]
fn boundary_allows_intersection() {
    let boundary = vec![stmt(Effect::Allow, &["s3:*"], &["*"])]; // no iam
    assert!(boundary_allows(&boundary, "s3:GetObject", "*"));
    assert!(!boundary_allows(&boundary, "iam:CreateUser", "*"));
}

#[test]
fn no_boundary_means_no_restriction() {
    let result = evaluate_with_boundary(&[], "iam:CreateUser", "*");
    assert_eq!(result, BoundaryResult::NoBoundary); // no restriction
}

#[test]
fn boundary_with_multiple_allow_statements() {
    let boundary = vec![
        stmt(Effect::Allow, &["s3:GetObject"], &["*"]),
        stmt(Effect::Allow, &["s3:ListBucket"], &["*"]),
    ];
    assert!(boundary_allows(&boundary, "s3:GetObject", "*"));
    assert!(boundary_allows(&boundary, "s3:ListBucket", "*"));
    assert!(!boundary_allows(&boundary, "s3:DeleteBucket", "*"));
}

#[test]
fn boundary_with_resource_pattern() {
    let boundary = vec![stmt(Effect::Allow, &["s3:*"], &["arn:aws:s3:::public-*"])];
    assert!(boundary_allows(
        &boundary,
        "s3:GetObject",
        "arn:aws:s3:::public-data"
    ));
    assert!(!boundary_allows(
        &boundary,
        "s3:GetObject",
        "arn:aws:s3:::private-data"
    ));
}

// ============================================================================
// Test group 4: SCP chain evaluation
// ============================================================================

#[test]
fn scp_chain_all_allow() {
    let root_scp = vec![stmt(Effect::Allow, &["*"], &["*"])];
    let ou_scp = vec![stmt(Effect::Allow, &["s3:*", "ec2:*"], &["*"])];
    let chain: &[&[PolicyStatement]] = &[&root_scp, &ou_scp];
    assert!(scp_allows(chain, "s3:GetObject", "*"));
}

#[test]
fn scp_chain_ou_blocks() {
    let root_scp = vec![stmt(Effect::Allow, &["*"], &["*"])];
    let ou_scp = vec![stmt(Effect::Allow, &["s3:*"], &["*"])]; // no iam
    let chain: &[&[PolicyStatement]] = &[&root_scp, &ou_scp];
    assert!(!scp_allows(chain, "iam:CreateUser", "*"));
}

#[test]
fn empty_scp_chain_means_no_restriction() {
    assert!(scp_allows(&[], "iam:CreateUser", "*"));
}

#[test]
fn scp_chain_requires_match_at_each_level() {
    let root_scp = vec![stmt(Effect::Allow, &["*"], &["*"])];
    let ou_scp = vec![stmt(Effect::Allow, &["s3:*"], &["*"])];
    let account_scp = vec![stmt(Effect::Allow, &["s3:Get*"], &["*"])]; // only Get* not *
    let chain: &[&[PolicyStatement]] = &[&root_scp, &ou_scp, &account_scp];
    assert!(scp_allows(chain, "s3:GetObject", "*")); // all levels allow
    assert!(!scp_allows(chain, "s3:DeleteBucket", "*")); // account_scp does NOT allow Delete*
}

// ============================================================================
// Test group 5: Condition evaluator (top 6 operators)
// ============================================================================

#[test]
fn string_equals_match() {
    assert!(evaluate_condition(
        "StringEquals",
        "aws:RequestedRegion",
        &["us-east-1"],
        "us-east-1"
    ));
}

#[test]
fn string_equals_no_match() {
    assert!(!evaluate_condition(
        "StringEquals",
        "aws:RequestedRegion",
        &["us-east-1"],
        "eu-west-1"
    ));
}

#[test]
fn string_not_equals_match() {
    assert!(evaluate_condition(
        "StringNotEquals",
        "aws:RequestedRegion",
        &["us-east-1"],
        "eu-west-1"
    ));
}

#[test]
fn string_not_equals_no_match() {
    assert!(!evaluate_condition(
        "StringNotEquals",
        "aws:RequestedRegion",
        &["us-east-1"],
        "us-east-1"
    ));
}

#[test]
fn string_like_wildcard() {
    assert!(evaluate_condition(
        "StringLike",
        "s3:prefix",
        &["home/*"],
        "home/alice/doc.txt"
    ));
}

#[test]
fn string_like_no_match() {
    assert!(!evaluate_condition(
        "StringLike",
        "s3:prefix",
        &["home/*"],
        "work/bob/file.txt"
    ));
}

#[test]
fn string_not_like_match() {
    assert!(evaluate_condition(
        "StringNotLike",
        "s3:prefix",
        &["home/*"],
        "work/bob/file.txt"
    ));
}

#[test]
fn string_not_like_no_match() {
    assert!(!evaluate_condition(
        "StringNotLike",
        "s3:prefix",
        &["home/*"],
        "home/alice/doc.txt"
    ));
}

#[test]
fn arn_like_match() {
    assert!(evaluate_condition(
        "ArnLike",
        "aws:SourceArn",
        &["arn:aws:s3:::my-*"],
        "arn:aws:s3:::my-bucket"
    ));
}

#[test]
fn arn_like_no_match() {
    assert!(!evaluate_condition(
        "ArnLike",
        "aws:SourceArn",
        &["arn:aws:s3:::my-*"],
        "arn:aws:s3:::other-bucket"
    ));
}

#[test]
fn arn_not_like_match() {
    assert!(evaluate_condition(
        "ArnNotLike",
        "aws:SourceArn",
        &["arn:aws:s3:::my-*"],
        "arn:aws:s3:::other-bucket"
    ));
}

#[test]
fn arn_not_like_no_match() {
    assert!(!evaluate_condition(
        "ArnNotLike",
        "aws:SourceArn",
        &["arn:aws:s3:::my-*"],
        "arn:aws:s3:::my-bucket"
    ));
}

#[test]
fn ip_address_cidr_match() {
    assert!(evaluate_condition(
        "IpAddress",
        "aws:SourceIp",
        &["10.0.0.0/8"],
        "10.1.2.3"
    ));
}

#[test]
fn ip_address_cidr_no_match() {
    assert!(!evaluate_condition(
        "IpAddress",
        "aws:SourceIp",
        &["10.0.0.0/8"],
        "192.168.1.1"
    ));
}

#[test]
fn ip_address_multiple_cidrs() {
    assert!(evaluate_condition(
        "IpAddress",
        "aws:SourceIp",
        &["10.0.0.0/8", "192.168.0.0/16"],
        "192.168.1.1"
    ));
}

#[test]
fn not_ip_address_match() {
    assert!(evaluate_condition(
        "NotIpAddress",
        "aws:SourceIp",
        &["10.0.0.0/8"],
        "192.168.1.1"
    ));
}

#[test]
fn not_ip_address_no_match() {
    assert!(!evaluate_condition(
        "NotIpAddress",
        "aws:SourceIp",
        &["10.0.0.0/8"],
        "10.1.2.3"
    ));
}

#[test]
fn null_condition_true() {
    assert!(evaluate_condition(
        "Null",
        "aws:MultiFactorAuthAge",
        &["true"],
        ""
    ));
}

#[test]
fn null_condition_false() {
    assert!(!evaluate_condition(
        "Null",
        "aws:MultiFactorAuthAge",
        &["true"],
        "3600"
    ));
}

#[test]
fn null_condition_false_with_false_value() {
    assert!(evaluate_condition(
        "Null",
        "aws:MultiFactorAuthAge",
        &["false"],
        "3600"
    ));
}

#[test]
fn bool_condition_true() {
    assert!(evaluate_condition(
        "Bool",
        "aws:SecureTransport",
        &["true"],
        "true"
    ));
}

#[test]
fn bool_condition_false() {
    assert!(!evaluate_condition(
        "Bool",
        "aws:SecureTransport",
        &["true"],
        "false"
    ));
}

#[test]
fn bool_condition_false_value() {
    assert!(evaluate_condition(
        "Bool",
        "aws:SecureTransport",
        &["false"],
        "false"
    ));
}

#[test]
fn unknown_operator_defaults_to_not_denied() {
    // Unevaluable conditions should not block — log warning, return true (not denied)
    assert!(evaluate_condition(
        "DateLessThan",
        "aws:CurrentTime",
        &["2026-12-31"],
        "2026-06-15"
    ));
}

#[test]
fn condition_matches_any_value_in_list() {
    // Condition with multiple values is OR semantics
    assert!(evaluate_condition(
        "StringEquals",
        "aws:RequestedRegion",
        &["us-east-1", "us-west-2", "eu-west-1"],
        "us-west-2"
    ));
}
