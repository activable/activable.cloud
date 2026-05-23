//! In-memory graph service adapter for risk scoring.
//!
//! Provides a working implementation of GraphQueryService using HashMap storage.
//! Production replacement: GraphClientAdapter wrapping real GraphClient (Phase 9).

use activable_risk::signals::{GraphQueryError, GraphQueryService, SignalError};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;

/// In-memory graph service that stores risk data and principal information.
///
/// This is a real working implementation that can be used for testing and
/// in environments where the full GraphClient is not yet available.
/// In production (Phase 9), this will be replaced with a GraphClientAdapter
/// that wraps the real GraphClient and executes actual Cypher queries.
pub struct InMemoryGraphService {
    principals: RwLock<PrincipalStore>,
}

struct PrincipalStore {
    principal_ids: Vec<String>,
    effective_permissions: HashMap<String, Vec<(String, String)>>,
    risk_assessments: HashMap<String, String>,
    reachable_counts: HashMap<String, u64>,
    shortest_paths: HashMap<String, Option<u32>>,
    cross_account_hops: HashMap<String, u32>,
}

impl InMemoryGraphService {
    /// Create a new, empty in-memory graph service.
    pub fn new() -> Self {
        Self {
            principals: RwLock::new(PrincipalStore {
                principal_ids: Vec::new(),
                effective_permissions: HashMap::new(),
                risk_assessments: HashMap::new(),
                reachable_counts: HashMap::new(),
                shortest_paths: HashMap::new(),
                cross_account_hops: HashMap::new(),
            }),
        }
    }

    /// Add a principal with its metadata. Used for testing and initialization.
    #[allow(dead_code)]
    pub fn add_principal(
        &self,
        principal_id: String,
        permissions: Vec<(String, String)>,
        reachable: u64,
        shortest_path: Option<u32>,
        cross_account_hops: u32,
    ) -> Result<(), SignalError> {
        let mut store = self
            .principals
            .write()
            .map_err(|e| Box::new(GraphQueryError(format!("lock failed: {}", e))) as SignalError)?;

        if !store.principal_ids.contains(&principal_id) {
            store.principal_ids.push(principal_id.clone());
        }
        store
            .effective_permissions
            .insert(principal_id.clone(), permissions);
        store
            .reachable_counts
            .insert(principal_id.clone(), reachable);
        store
            .shortest_paths
            .insert(principal_id.clone(), shortest_path);
        store
            .cross_account_hops
            .insert(principal_id, cross_account_hops);
        Ok(())
    }
}

impl Default for InMemoryGraphService {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl GraphQueryService for InMemoryGraphService {
    async fn reachable_count(&self, principal_id: &str, _max_hops: u8) -> Result<u64, SignalError> {
        let store = self
            .principals
            .read()
            .map_err(|e| Box::new(GraphQueryError(format!("lock failed: {}", e))) as SignalError)?;
        Ok(store
            .reachable_counts
            .get(principal_id)
            .copied()
            .unwrap_or(0))
    }

    async fn shortest_path_to_admin(
        &self,
        principal_id: &str,
        _max_depth: u8,
    ) -> Result<Option<u32>, SignalError> {
        let store = self
            .principals
            .read()
            .map_err(|e| Box::new(GraphQueryError(format!("lock failed: {}", e))) as SignalError)?;
        Ok(store.shortest_paths.get(principal_id).copied().flatten())
    }

    async fn cross_account_hop_count(&self, principal_id: &str) -> Result<u32, SignalError> {
        let store = self
            .principals
            .read()
            .map_err(|e| Box::new(GraphQueryError(format!("lock failed: {}", e))) as SignalError)?;
        Ok(store
            .cross_account_hops
            .get(principal_id)
            .copied()
            .unwrap_or(0))
    }

    async fn list_principal_ids(&self) -> Result<Vec<String>, SignalError> {
        let store = self
            .principals
            .read()
            .map_err(|e| Box::new(GraphQueryError(format!("lock failed: {}", e))) as SignalError)?;
        Ok(store.principal_ids.clone())
    }

    async fn get_effective_permissions(
        &self,
        principal_id: &str,
    ) -> Result<Vec<(String, String)>, SignalError> {
        let store = self
            .principals
            .read()
            .map_err(|e| Box::new(GraphQueryError(format!("lock failed: {}", e))) as SignalError)?;
        Ok(store
            .effective_permissions
            .get(principal_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn read_risk_assessment(
        &self,
        principal_id: &str,
    ) -> Result<Option<String>, SignalError> {
        let store = self
            .principals
            .read()
            .map_err(|e| Box::new(GraphQueryError(format!("lock failed: {}", e))) as SignalError)?;
        Ok(store.risk_assessments.get(principal_id).cloned())
    }

    async fn write_risk_assessment(
        &self,
        principal_id: &str,
        assessment_json: &str,
    ) -> Result<(), SignalError> {
        let mut store = self
            .principals
            .write()
            .map_err(|e| Box::new(GraphQueryError(format!("lock failed: {}", e))) as SignalError)?;
        store
            .risk_assessments
            .insert(principal_id.to_string(), assessment_json.to_string());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn add_principal_and_retrieve() {
        let service = InMemoryGraphService::new();

        service
            .add_principal(
                "principal-1".to_string(),
                vec![(
                    "iam:CreateAccessKey".to_string(),
                    "arn:aws:iam::123456789012:user/*".to_string(),
                )],
                100,
                Some(3),
                2,
            )
            .unwrap();

        let ids = service.list_principal_ids().await.unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], "principal-1");

        let perms = service
            .get_effective_permissions("principal-1")
            .await
            .unwrap();
        assert_eq!(perms.len(), 1);
        assert_eq!(perms[0].0, "iam:CreateAccessKey");

        let reachable = service.reachable_count("principal-1", 6).await.unwrap();
        assert_eq!(reachable, 100);
    }

    #[tokio::test]
    async fn read_write_risk_assessment() {
        let service = InMemoryGraphService::new();

        service
            .add_principal("principal-1".to_string(), vec![], 0, None, 0)
            .unwrap();

        let assessment_json = r#"{"principal_id":"principal-1","score":0.75,"severity":"High"}"#;
        service
            .write_risk_assessment("principal-1", assessment_json)
            .await
            .unwrap();

        let cached = service.read_risk_assessment("principal-1").await.unwrap();
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), assessment_json);
    }

    #[tokio::test]
    async fn multiple_principals() {
        let service = InMemoryGraphService::new();

        service
            .add_principal(
                "principal-1".to_string(),
                vec![(
                    "iam:CreateAccessKey".to_string(),
                    "arn:aws:iam::123456789012:user/*".to_string(),
                )],
                100,
                Some(3),
                2,
            )
            .unwrap();

        service
            .add_principal(
                "principal-2".to_string(),
                vec![(
                    "s3:GetObject".to_string(),
                    "arn:aws:s3:::bucket".to_string(),
                )],
                0,
                None,
                0,
            )
            .unwrap();

        let ids = service.list_principal_ids().await.unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"principal-1".to_string()));
        assert!(ids.contains(&"principal-2".to_string()));
    }
}
