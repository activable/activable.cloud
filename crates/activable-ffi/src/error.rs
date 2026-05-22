//! FFI-safe error type for UniFFI boundary.

use std::fmt;

#[derive(Debug, Clone, uniffi::Error)]
pub enum ActivableError {
    AlreadyInitialized,
    NotInitialized,
    InvalidInput { message: String },
    GraphError { message: String },
    PoolExhausted,
}

impl fmt::Display for ActivableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyInitialized => write!(f, "runtime already initialized"),
            Self::NotInitialized => {
                write!(f, "runtime not initialized; call graph_initialize first")
            }
            Self::InvalidInput { message } => write!(f, "invalid input: {}", message),
            Self::GraphError { message } => write!(f, "graph error: {}", message),
            Self::PoolExhausted => write!(f, "connection pool exhausted"),
        }
    }
}

impl From<activable_graph::GraphError> for ActivableError {
    fn from(err: activable_graph::GraphError) -> Self {
        match err {
            activable_graph::GraphError::Pool(msg) => {
                if msg.contains("exhausted") {
                    Self::PoolExhausted
                } else {
                    Self::GraphError {
                        message: format!("pool error: {}", msg),
                    }
                }
            }
            activable_graph::GraphError::Query(msg) => Self::GraphError {
                message: format!("query error: {}", msg),
            },
            activable_graph::GraphError::NotFound => Self::GraphError {
                message: "node not found".to_string(),
            },
            activable_graph::GraphError::UnsafeParameter(msg) => {
                Self::InvalidInput { message: msg }
            }
            activable_graph::GraphError::PoolExhausted => Self::PoolExhausted,
            activable_graph::GraphError::Parse(msg) => Self::GraphError {
                message: format!("parse error: {}", msg),
            },
        }
    }
}
