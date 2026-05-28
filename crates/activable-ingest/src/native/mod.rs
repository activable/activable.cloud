//! Native AWS SDK enrichers that run after CCAPI/fallback ingestion.
//!
//! These enrichers add relationship edges to the graph that CCAPI doesn't provide:
//! - IAM trust policies → CanAssume/TrustedBy edges
//! - IAM inline policies → HasEffectivePermission edges (permissions enricher)
//! - EC2 security groups → HasSecurityGroup edges
//! - S3 bucket policies → access edges
//! - KMS key policies → access edges + grantable edges
//! - Lambda resource policies → access edges

pub mod access_edges;
pub mod ec2;
pub mod iam;
pub mod kms;
pub mod lambda;
pub mod permissions;
pub mod principal;
pub mod resource_policy;
pub mod s3;
pub mod secretsmanager;
pub mod sentinel;

use crate::error::IngestError;
use async_trait::async_trait;
use deadpool_postgres::Pool;
use std::sync::Arc;

/// Statistics from a single enricher's execution.
#[derive(Debug, Clone)]
pub struct EnrichmentStats {
    /// Service name (e.g., "iam", "ec2", "s3").
    pub service: String,
    /// Number of edges created during enrichment.
    pub edges_created: u32,
}

/// Trait for AWS service enrichers that add relationship edges to the graph.
#[async_trait]
pub trait NativeEnricher: Send + Sync {
    /// Returns the service name (e.g., "iam", "ec2", "s3").
    fn service(&self) -> &str;

    /// Runs enrichment for this service, querying AWS and adding edges to the graph.
    /// Existing nodes are assumed to already be in the graph from Phase 1 ingestion.
    async fn enrich(
        &self,
        pool: &Arc<Pool>,
        graph_name: &str,
    ) -> Result<EnrichmentStats, IngestError>;
}
