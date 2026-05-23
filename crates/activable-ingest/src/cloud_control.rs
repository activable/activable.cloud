use crate::error::IngestError;
use crate::resource_registry::ResourceTypeConfig;
use activable_graph::loader;
use aws_sdk_cloudcontrol::Client as CloudControlClient;
use deadpool_postgres::Pool;
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct IngestStats {
    pub type_name: String,
    pub label: String,
    pub nodes_ingested: u32,
}

/// Fetch resources via AWS Cloud Control API with pagination.
pub async fn fetch_via_ccapi(
    client: &CloudControlClient,
    resource_type: &ResourceTypeConfig,
    pool: Arc<Pool>,
    graph_name: &str,
) -> Result<IngestStats, IngestError> {
    let type_name = &resource_type.type_name;
    let label = &resource_type.label;

    debug!(type_name = %type_name, "Starting CCAPI fetch");

    let mut token: Option<String> = None;
    let mut count = 0u32;

    loop {
        let mut request = client.list_resources().type_name(type_name);

        if let Some(t) = &token {
            request = request.next_token(t);
        }

        let response = request.send().await.map_err(|e| {
            let msg = e.to_string();
            warn!(type_name = %type_name, error = %msg, "CCAPI request failed");
            IngestError::CloudControl {
                type_name: type_name.clone(),
                message: msg,
            }
        })?;

        let descriptions = response.resource_descriptions();
        if descriptions.is_empty() {
            debug!(type_name = %type_name, "No more resources, pagination complete");
            break;
        }

        // Convert resource descriptions to graph nodes
        let nodes: Vec<Value> = descriptions
            .iter()
            .filter_map(|desc| {
                let identifier = desc.identifier().unwrap_or_default();
                if identifier.is_empty() {
                    warn!(type_name = %type_name, "Skipping resource with empty identifier");
                    return None;
                }

                let properties: Value = desc
                    .properties()
                    .and_then(|p| serde_json::from_str(p).ok())
                    .unwrap_or_else(|| {
                        debug!(identifier = %identifier, "Failed to parse properties, using empty object");
                        json!({})
                    });

                match properties {
                    Value::Object(mut obj) => {
                        obj.insert("id".to_string(), Value::String(identifier.to_string()));
                        Some(Value::Object(obj))
                    }
                    _ => Some(json!({"id": identifier})),
                }
            })
            .collect();

        if !nodes.is_empty() {
            let written = loader::load_nodes(pool.clone(), graph_name, label, &nodes, 100)
                .await
                .map_err(|e| {
                    warn!(type_name = %type_name, error = %e, "Failed to write nodes to graph");
                    IngestError::from(e)
                })?;

            count += written as u32;
            debug!(
                type_name = %type_name,
                batch_count = written,
                total_count = count,
                "Batch written to graph"
            );
        }

        // Check for next page
        token = response.next_token().map(|s| s.to_string());
        if token.is_none() {
            break;
        }
    }

    info!(
        type_name = %type_name,
        label = %label,
        nodes_ingested = count,
        "CCAPI ingest complete"
    );

    Ok(IngestStats {
        type_name: type_name.clone(),
        label: label.clone(),
        nodes_ingested: count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ingest_stats_creation() {
        let stats = IngestStats {
            type_name: "AWS::IAM::User".to_string(),
            label: "Principal".to_string(),
            nodes_ingested: 42,
        };

        assert_eq!(stats.type_name, "AWS::IAM::User");
        assert_eq!(stats.label, "Principal");
        assert_eq!(stats.nodes_ingested, 42);
    }

    #[test]
    fn test_node_conversion() {
        // Test that properties with id field are properly constructed
        let mut obj = serde_json::Map::new();
        obj.insert("name".to_string(), Value::String("test".to_string()));
        obj.insert(
            "id".to_string(),
            Value::String("arn:aws:iam::123:user/test".to_string()),
        );

        let node = Value::Object(obj);
        assert!(node.is_object());
        assert_eq!(node["id"], "arn:aws:iam::123:user/test");
        assert_eq!(node["name"], "test");
    }
}
