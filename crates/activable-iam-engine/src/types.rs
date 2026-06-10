//! Core types for IAM policy representation.

use serde::{Deserialize, Serialize};

/// The effect of a policy statement: Allow or Deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Effect {
    Allow,
    Deny,
}

/// A wildcard pattern for an IAM action (e.g., "s3:GetObject", "s3:Get*", "*").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionPattern(pub String);

/// A wildcard pattern for an IAM resource ARN (e.g., "arn:aws:s3:::my-bucket/*", "*").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePattern(pub String);

/// A single condition within a policy statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Condition {
    /// The condition operator (e.g., "StringEquals", "IpAddress", "ArnLike").
    pub operator: String,
    /// The condition key (e.g., "aws:SourceIp", "s3:prefix").
    pub key: String,
    /// The values to match against.
    pub values: Vec<String>,
}

/// A single statement within an IAM policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyStatement {
    /// Optional Sid (statement ID) for reference.
    pub sid: Option<String>,
    /// The effect: Allow or Deny.
    pub effect: Effect,
    /// Actions this statement applies to.
    pub actions: Vec<ActionPattern>,
    /// Actions explicitly NOT covered by this statement (mutually exclusive with actions).
    pub not_actions: Vec<ActionPattern>,
    /// Resources (ARNs) this statement applies to.
    pub resources: Vec<ResourcePattern>,
    /// Resources explicitly NOT covered by this statement (mutually exclusive with resources).
    pub not_resources: Vec<ResourcePattern>,
    /// Conditions that must be met for this statement to apply.
    pub conditions: Vec<Condition>,
}

/// A fully parsed IAM policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPolicy {
    /// The policy language version (e.g., "2012-10-17").
    pub version: String,
    /// The statements in this policy.
    pub statements: Vec<PolicyStatement>,
}
