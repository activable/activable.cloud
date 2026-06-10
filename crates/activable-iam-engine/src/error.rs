//! Error types for IAM policy parsing and evaluation.

use thiserror::Error;

/// Errors that can occur during IAM policy parsing.
#[derive(Error, Debug)]
pub enum PolicyParseError {
    #[error("invalid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("missing required field: {0}")]
    MissingField(String),

    #[error("invalid effect value: {0}. Must be 'Allow' or 'Deny'")]
    InvalidEffect(String),

    #[error("mutually exclusive: both Action and NotAction present in same statement")]
    ActionAndNotActionTogether,

    #[error("mutually exclusive: both Resource and NotResource present in same statement")]
    ResourceAndNotResourceTogether,

    #[error("invalid statement: {0}")]
    InvalidStatement(String),
}

pub type PolicyParseResult<T> = Result<T, PolicyParseError>;
