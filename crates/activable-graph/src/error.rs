//! Error types for the graph client.
//!
//! Provides typed error variants for pool operations, query execution,
//! and parameter validation.

use thiserror::Error;

/// Result type alias for graph operations.
pub type GraphResult<T> = Result<T, GraphError>;

/// Typed errors for graph operations.
///
/// All graph operations return this error type, allowing callers to
/// distinguish between pool exhaustion, query failures, not-found conditions,
/// and parameter validation errors programmatically.
#[derive(Debug, Error)]
pub enum GraphError {
    /// Connection pool operation failed.
    #[error("pool error: {0}")]
    Pool(#[from] deadpool_postgres::PoolError),

    /// Query execution failed.
    #[error("query error: {0}")]
    Query(#[from] tokio_postgres::Error),

    /// Node or path not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Invalid parameter detected (Cypher injection guard).
    #[error("unsafe parameter: {0}")]
    UnsafeParameter(String),

    /// Graph name is invalid (must be a valid identifier).
    #[error("invalid graph name: {0}")]
    InvalidGraphName(String),

    /// Label is invalid (must be a valid identifier).
    #[error("invalid label: {0}")]
    InvalidLabel(String),

    /// Generic graph error.
    #[error("{0}")]
    Other(String),
}

impl GraphError {
    /// Create a "not found" error with the given context.
    pub fn not_found(context: impl Into<String>) -> Self {
        Self::NotFound(context.into())
    }

    /// Create an "unsafe parameter" error with the given context.
    pub fn unsafe_parameter(context: impl Into<String>) -> Self {
        Self::UnsafeParameter(context.into())
    }

    /// Create an "invalid graph name" error.
    pub fn invalid_graph_name(name: impl Into<String>) -> Self {
        Self::InvalidGraphName(name.into())
    }

    /// Create an "invalid label" error.
    pub fn invalid_label(label: impl Into<String>) -> Self {
        Self::InvalidLabel(label.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = GraphError::not_found("test_node");
        assert_eq!(err.to_string(), "not found: test_node");
    }

    #[test]
    fn test_unsafe_parameter_error() {
        let err = GraphError::unsafe_parameter("invalid_char_here");
        assert!(err.to_string().contains("unsafe parameter"));
    }

    #[test]
    fn test_invalid_label_error() {
        let err = GraphError::invalid_label("123Invalid");
        assert!(err.to_string().contains("invalid label"));
    }
}
