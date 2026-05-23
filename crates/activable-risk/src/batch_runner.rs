use crate::config::RiskConfig;
use crate::finding::RiskAssessment;
use crate::rule_engine::{match_all_rules, EffectivePermission};
use crate::scorer::score_principal;
use crate::signals::{
    BlastRadiusSignal, CrossAccountHopsSignal, DangerousActionCountSignal, GraphQueryService,
    PathToAdminSignal, PermissionSurfaceSignal, SignalError,
};
use crate::types::EscalationRule;

/// Result of a batch scoring run
#[derive(Debug)]
pub struct BatchResult {
    pub assessments: Vec<RiskAssessment>,
    pub total_principals: usize,
    pub scored_count: usize,
    pub skipped_stale: usize,
    pub errors: Vec<(String, String)>, // (principal_id, error_message)
}

/// Score a single principal given their effective permissions and graph access.
///
/// Computes all five signals (graph-based and pure-Rust), matches rules,
/// and produces a complete RiskAssessment.
pub async fn score_single_principal(
    principal_id: &str,
    effective_perms: &[EffectivePermission],
    rules: &[EscalationRule],
    graph: &dyn GraphQueryService,
    config: &RiskConfig,
    computed_at: &str,
) -> Result<RiskAssessment, SignalError> {
    // Compute graph-based signals
    let blast_radius_signal = BlastRadiusSignal::new();
    let blast_radius = blast_radius_signal.compute(principal_id, graph, 6).await?;

    let path_to_admin_signal = PathToAdminSignal::new(8);
    let path_to_admin = path_to_admin_signal.compute(principal_id, graph).await?;

    let cross_account_signal = CrossAccountHopsSignal;
    let cross_account = cross_account_signal.compute(principal_id, graph).await?;

    // Compute pure-Rust signals
    let dangerous_actions_signal = DangerousActionCountSignal;
    let dangerous_actions = dangerous_actions_signal.compute_sync(effective_perms);

    let permission_surface_signal = PermissionSurfaceSignal;
    let permission_surface = permission_surface_signal.compute_sync(effective_perms);

    // Combine all signal results
    let signal_results = vec![
        blast_radius,
        path_to_admin,
        dangerous_actions,
        cross_account,
        permission_surface,
    ];

    // Match rules against effective permissions
    let matched_rules = match_all_rules(rules, effective_perms);

    // Score the principal
    let assessment = score_principal(
        principal_id,
        signal_results,
        matched_rules,
        config,
        computed_at,
    );

    Ok(assessment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    struct MockGraph {
        reachable_counts: HashMap<String, u64>,
        shortest_paths: HashMap<String, Option<u32>>,
        cross_account_hops: HashMap<String, u32>,
    }

    #[async_trait::async_trait]
    impl GraphQueryService for MockGraph {
        async fn reachable_count(
            &self,
            principal_id: &str,
            _max_hops: u8,
        ) -> Result<u64, SignalError> {
            Ok(self
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
            Ok(self.shortest_paths.get(principal_id).copied().flatten())
        }

        async fn cross_account_hop_count(&self, principal_id: &str) -> Result<u32, SignalError> {
            Ok(self
                .cross_account_hops
                .get(principal_id)
                .copied()
                .unwrap_or(0))
        }
    }

    #[tokio::test]
    async fn score_single_principal_with_all_signals() {
        let config = RiskConfig::default();
        let mut reachable_counts = HashMap::new();
        reachable_counts.insert("principal-1".to_string(), 100);

        let mut shortest_paths = HashMap::new();
        shortest_paths.insert("principal-1".to_string(), Some(3));

        let mut cross_account_hops = HashMap::new();
        cross_account_hops.insert("principal-1".to_string(), 2);

        let graph = MockGraph {
            reachable_counts,
            shortest_paths,
            cross_account_hops,
        };

        let effective_perms = vec![
            EffectivePermission::new("iam:CreateAccessKey", "arn:aws:iam::123456789012:user/*"),
            EffectivePermission::new("iam:AttachUserPolicy", "arn:aws:iam::123456789012:*"),
        ];

        let rules = vec![];

        let assessment = score_single_principal(
            "principal-1",
            &effective_perms,
            &rules,
            &graph,
            &config,
            "2026-05-23T10:00:00Z",
        )
        .await
        .unwrap();

        assert_eq!(assessment.principal_id, "principal-1");
        assert!(assessment.score > 0.0);
        assert_eq!(assessment.signal_contributions.len(), 5);
    }

    #[tokio::test]
    async fn score_single_principal_zero_risk() {
        let config = RiskConfig::default();
        let mut reachable_counts = HashMap::new();
        reachable_counts.insert("principal-2".to_string(), 0);

        let graph = MockGraph {
            reachable_counts,
            shortest_paths: HashMap::new(),
            cross_account_hops: HashMap::new(),
        };

        let effective_perms = vec![EffectivePermission::new(
            "s3:GetObject",
            "arn:aws:s3:::bucket",
        )];
        let rules = vec![];

        let assessment = score_single_principal(
            "principal-2",
            &effective_perms,
            &rules,
            &graph,
            &config,
            "2026-05-23T10:00:00Z",
        )
        .await
        .unwrap();

        assert_eq!(assessment.principal_id, "principal-2");
        // Score should be low (safe permissions, no escalation)
        assert!(assessment.score < 0.5);
    }
}
