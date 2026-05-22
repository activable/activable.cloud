use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum IngestError {
    #[error("AWS SDK error: {0}")]
    AwsSdk(String),

    #[error("Cloud Control API error for {type_name}: {message}")]
    CloudControl { type_name: String, message: String },

    #[error("graph write error: {0}")]
    Graph(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("YAML parse error: {0}")]
    YamlParse(String),

    #[error("resource registry not loaded")]
    RegistryNotLoaded,

    #[error("io error: {0}")]
    IoError(String),
}

impl From<activable_graph::error::GraphError> for IngestError {
    fn from(err: activable_graph::error::GraphError) -> Self {
        IngestError::Graph(err.to_string())
    }
}

impl From<std::io::Error> for IngestError {
    fn from(err: std::io::Error) -> Self {
        IngestError::IoError(err.to_string())
    }
}
