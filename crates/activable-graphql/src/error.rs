//! Error mapping from activable-graph to async-graphql errors.

use async_graphql::{Error as GqlError, ErrorExtensions};
use activable_graph::error::GraphError;

/// Map a GraphError to an async-graphql Error with extensions.
///
/// Do NOT leak raw database error messages to clients. Log them internally,
/// return generic messages.
pub fn map_graph_error(error: GraphError) -> GqlError {
    match error {
        GraphError::NotFound => GqlError::new("Resource not found")
            .extend_with(|_, e| e.set("code", "NOT_FOUND")),
        GraphError::PoolExhausted => GqlError::new("Service temporarily unavailable")
            .extend_with(|_, e| e.set("code", "POOL_EXHAUSTED")),
        GraphError::UnsafeParameter(_) => GqlError::new("Invalid parameter")
            .extend_with(|_, e| e.set("code", "INVALID_PARAMETER")),
        GraphError::Pool(_) | GraphError::Query(_) | GraphError::Parse(_) => {
            GqlError::new("Internal server error")
                .extend_with(|_, e| e.set("code", "INTERNAL_ERROR"))
        }
    }
}
