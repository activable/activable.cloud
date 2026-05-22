//! FFI error type — bridges graph errors to the UniFFI boundary.

use activable_graph::GraphError;
use thiserror::Error;

/// FFI-safe error type, serializable across the Rust↔Go boundary.
///
/// All graph operations and FFI initialization errors map to one of these variants.
/// UniFFI requires enum variants to be simple — no nested generics or complex types.
#[derive(Debug, Error, uniffi::Error)]
pub enum ActivableError {
    /// The global runtime was already initialized (second call to `graph_initialize`).
    #[error("already initialized")]
    AlreadyInitialized,

    /// The global runtime is not initialized — `graph_initialize` must be called first.
    #[error("not initialized")]
    NotInitialized,

    /// Invalid input: JSON deserialization, parameter validation, etc.
    #[error("invalid input: {message}")]
    InvalidInput { message: String },

    /// Graph operation failed (query, insert, constraint violation, etc.).
    #[error("graph error: {message}")]
    GraphError { message: String },

    /// Connection pool exhausted or unable to acquire connection.
    #[error("pool exhausted")]
    PoolExhausted,
}

impl From<GraphError> for ActivableError {
    fn from(err: GraphError) -> Self {
        // Map GraphError variants to ActivableError variants for safe FFI transmission.
        match err {
            GraphError::Pool(pool_err) => {
                if pool_err.to_string().contains("exhausted") {
                    ActivableError::PoolExhausted
                } else {
                    ActivableError::GraphError {
                        message: pool_err.to_string(),
                    }
                }
            }
            GraphError::Query(query_err) => ActivableError::GraphError {
                message: query_err.to_string(),
            },
            GraphError::NotFound(msg) => ActivableError::GraphError {
                message: format!("not found: {}", msg),
            },
            GraphError::UnsafeParameter(msg) => ActivableError::InvalidInput {
                message: format!("unsafe parameter: {}", msg),
            },
            GraphError::InvalidGraphName(msg) => ActivableError::InvalidInput {
                message: format!("invalid graph name: {}", msg),
            },
            GraphError::InvalidLabel(msg) => ActivableError::InvalidInput {
                message: format!("invalid label: {}", msg),
            },
            GraphError::Other(msg) => ActivableError::GraphError { message: msg },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_not_found_mapping() {
        let graph_err = GraphError::not_found("test_node");
        let ffi_err: ActivableError = graph_err.into();
        assert!(matches!(ffi_err, ActivableError::GraphError { .. }));
    }

    #[test]
    fn test_error_unsafe_parameter_mapping() {
        let graph_err = GraphError::unsafe_parameter("dangerous_input");
        let ffi_err: ActivableError = graph_err.into();
        assert!(matches!(ffi_err, ActivableError::InvalidInput { .. }));
    }

    #[test]
    fn test_error_invalid_graph_name_mapping() {
        let graph_err = GraphError::invalid_graph_name("123-invalid");
        let ffi_err: ActivableError = graph_err.into();
        assert!(matches!(ffi_err, ActivableError::InvalidInput { .. }));
    }

    #[test]
    fn test_error_invalid_label_mapping() {
        let graph_err = GraphError::invalid_label("invalid label");
        let ffi_err: ActivableError = graph_err.into();
        assert!(matches!(ffi_err, ActivableError::InvalidInput { .. }));
    }

    #[test]
    fn test_error_already_initialized() {
        let err = ActivableError::AlreadyInitialized;
        let msg = err.to_string();
        assert!(msg.contains("already initialized"));
    }

    #[test]
    fn test_error_not_initialized() {
        let err = ActivableError::NotInitialized;
        let msg = err.to_string();
        assert!(msg.contains("not initialized"));
    }

    #[test]
    fn test_error_invalid_input() {
        let err = ActivableError::InvalidInput {
            message: "test error".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("invalid input"));
        assert!(msg.contains("test error"));
    }

    #[test]
    fn test_error_graph_error() {
        let err = ActivableError::GraphError {
            message: "query failed".to_string(),
        };
        let msg = err.to_string();
        assert!(msg.contains("graph error"));
        assert!(msg.contains("query failed"));
    }

    #[test]
    fn test_error_pool_exhausted() {
        let err = ActivableError::PoolExhausted;
        let msg = err.to_string();
        assert!(msg.contains("pool exhausted"));
    }
}
