//! EC2 enricher: creates HasSecurityGroup edges from instances to security groups.

use crate::error::IngestError;
use crate::native::{EnrichmentStats, NativeEnricher};
use activable_graph::loader::load_edges;
use async_trait::async_trait;
use aws_config::SdkConfig;
use deadpool_postgres::Pool;
use std::sync::Arc;
use tracing::debug;

/// EC2 enricher that creates edges between instances and their security groups.
pub struct Ec2Enricher {
    config: SdkConfig,
}

impl Ec2Enricher {
    /// Create a new EC2 enricher with the given AWS config.
    pub fn new(config: SdkConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl NativeEnricher for Ec2Enricher {
    fn service(&self) -> &str {
        "ec2"
    }

    async fn enrich(
        &self,
        pool: &Arc<Pool>,
        graph_name: &str,
    ) -> Result<EnrichmentStats, IngestError> {
        let client = aws_sdk_ec2::Client::new(&self.config);
        let mut edges: Vec<(String, String)> = Vec::new();

        debug!("Starting EC2 enrichment");

        // Describe all instances to find security group relationships
        let mut paginator = client.describe_instances().into_paginator().send();
        while let Some(page) = paginator.next().await {
            let page = page.map_err(|e| {
                IngestError::AwsSdk(format!("Failed to describe EC2 instances: {}", e))
            })?;

            for reservation in page.reservations() {
                for instance in reservation.instances() {
                    let Some(instance_id) = instance.instance_id() else {
                        continue;
                    };
                    let instance_id_str = instance_id.to_string();

                    // Extract security groups associated with this instance
                    for sg in instance.security_groups() {
                        if let Some(sg_id) = sg.group_id() {
                            // Edge from instance to security group
                            edges.push((instance_id_str.clone(), sg_id.to_string()));
                        }
                    }
                }
            }
        }

        // Write HasSecurityGroup edges in batches
        let mut edge_count = 0u32;
        if !edges.is_empty() {
            debug!(edge_count = edges.len(), "Writing HasSecurityGroup edges");
            let outcome = load_edges(
                pool.clone(),
                graph_name,
                "HasSecurityGroup",
                &edges,
                100,
                false,
            )
            .await?;
            debug!(
                created = outcome.created,
                dropped = outcome.dropped,
                "HasSecurityGroup edges outcome"
            );
            edge_count = outcome.created as u32;
        }

        Ok(EnrichmentStats {
            service: self.service().to_string(),
            edges_created: edge_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enricher_has_service_name() {
        let enricher = Ec2Enricher::new(aws_config::SdkConfig::builder().build());
        assert_eq!(enricher.service(), "ec2");
    }
}
