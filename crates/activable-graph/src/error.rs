//! Graph operation error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GraphError {
    #[error("pool error: {0}")]
    Pool(String),

    #[error("query error: {0}")]
    Query(String),

    #[error("node not found")]
    NotFound,

    #[error("unsafe parameter: {0}")]
    UnsafeParameter(String),

    #[error("pool exhausted")]
    PoolExhausted,

    #[error("parse error: {0}")]
    Parse(String),
}

impl From<deadpool_postgres::PoolError> for GraphError {
    fn from(err: deadpool_postgres::PoolError) -> Self {
        GraphError::Pool(err.to_string())
    }
}

impl From<tokio_postgres::Error> for GraphError {
    fn from(err: tokio_postgres::Error) -> Self {
        GraphError::Query(err.to_string())
    }
}
