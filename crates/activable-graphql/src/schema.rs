//! GraphQL schema definition: Query and Mutation root types.

use crate::resolvers;
use crate::types::*;
use async_graphql::{Context, EmptySubscription, Object, Schema};

/// Type alias for the complete GraphQL schema.
pub type AppSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

/// Root query type.
pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Find a node by its label and ID.
    async fn find_node(
        &self,
        ctx: &Context<'_>,
        label: String,
        id: String,
    ) -> async_graphql::Result<Option<GqlNode>> {
        resolvers::node::find_node(ctx, label, id).await
    }

    /// Walk edges one hop from a starting node, returning up to `limit` neighbors.
    async fn walk_edges(
        &self,
        ctx: &Context<'_>,
        start: String,
        edge_types: Vec<String>,
        direction: String,
        limit: i32,
    ) -> async_graphql::Result<Vec<GqlNodeRef>> {
        resolvers::traversal::walk_edges(ctx, start, edge_types, direction, limit).await
    }

    /// Find paths between two nodes.
    async fn path_finder(
        &self,
        ctx: &Context<'_>,
        start: String,
        end: String,
        edge_pattern: Vec<String>,
        max_hops: i32,
    ) -> async_graphql::Result<Vec<GqlPath>> {
        resolvers::path::path_finder(ctx, start, end, edge_pattern, max_hops).await
    }

    /// Find all nodes within a given depth from a starting node.
    async fn blast_radius(
        &self,
        ctx: &Context<'_>,
        node: String,
        depth: i32,
    ) -> async_graphql::Result<Vec<GqlNodeRef>> {
        resolvers::traversal::blast_radius(ctx, node, depth).await
    }

    /// Get a subgraph around a center node.
    async fn subgraph(
        &self,
        ctx: &Context<'_>,
        center: String,
        radius: i32,
    ) -> async_graphql::Result<GqlSubgraph> {
        resolvers::subgraph::subgraph(ctx, center, radius).await
    }

    /// Get the status of a previous ingest run (job).
    async fn ingest_status(
        &self,
        ctx: &Context<'_>,
        job_id: String,
    ) -> async_graphql::Result<Option<GqlIngestRun>> {
        resolvers::ingest::ingest_status(ctx, job_id).await
    }

    /// List ingestion jobs with optional filters.
    async fn ingest_jobs(
        &self,
        ctx: &Context<'_>,
        filter: Option<GqlIngestJobFilter>,
    ) -> async_graphql::Result<Vec<GqlIngestRun>> {
        resolvers::ingest::ingest_jobs(ctx, filter).await
    }

    /// Check the health of the GraphQL server and database.
    async fn healthz(&self, ctx: &Context<'_>) -> async_graphql::Result<String> {
        resolvers::health::healthz(ctx).await
    }

    /// Get risk assessment for a principal.
    async fn risk_score(
        &self,
        ctx: &Context<'_>,
        principal_id: String,
    ) -> async_graphql::Result<GqlRiskAssessment> {
        resolvers::risk::risk_score(ctx, principal_id).await
    }

    /// List all risk findings above a minimum severity threshold.
    async fn findings(
        &self,
        ctx: &Context<'_>,
        min_severity: Option<GqlSeverity>,
        limit: Option<i32>,
    ) -> async_graphql::Result<Vec<GqlRiskAssessment>> {
        resolvers::risk::findings(ctx, min_severity, limit).await
    }

    /// Get key management risks for a KMS key.
    async fn key_management_risks(
        &self,
        ctx: &Context<'_>,
        key_id: String,
    ) -> async_graphql::Result<GqlKeyManagementRisks> {
        resolvers::key_management_risks::key_management_risks(ctx, key_id).await
    }

    /// Get resource policy risks for a bucket or KMS key.
    async fn resource_policy_risks(
        &self,
        ctx: &Context<'_>,
        bucket_name: Option<String>,
        key_id: Option<String>,
    ) -> async_graphql::Result<Option<GqlResourcePolicyRisks>> {
        resolvers::resource_policy_risks::resource_policy_risks(ctx, bucket_name, key_id).await
    }

    /// Get account-level risks aggregated across all principals.
    async fn account_risks(
        &self,
        ctx: &Context<'_>,
        account_id: String,
    ) -> async_graphql::Result<GqlAccountRisks> {
        resolvers::account_risks::account_risks(ctx, account_id).await
    }

    /// Get federation (OIDC) risks for an AWS account.
    async fn federation_risks(
        &self,
        ctx: &Context<'_>,
        account_id: String,
    ) -> async_graphql::Result<GqlFederationRisks> {
        resolvers::federation_risks::federation_risks(ctx, account_id).await
    }
}

/// Root mutation type.
pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// Trigger a new ingestion run (enqueues per-account jobs).
    async fn trigger_ingest(
        &self,
        ctx: &Context<'_>,
        provider: String,
        regions: Vec<String>,
        #[graphql(
            desc = "List of AWS account IDs to ingest (12-digit strings). If omitted, uses configured default accounts."
        )]
        account_ids: Option<Vec<String>>,
    ) -> async_graphql::Result<Vec<String>> {
        resolvers::ingest::trigger_ingest(ctx, provider, regions, account_ids).await
    }

    /// Refresh (re-score) a principal's risk assessment.
    async fn refresh_risk_score(
        &self,
        ctx: &Context<'_>,
        principal_id: String,
    ) -> async_graphql::Result<GqlRiskAssessment> {
        resolvers::risk::refresh_risk_score(ctx, principal_id).await
    }
}
