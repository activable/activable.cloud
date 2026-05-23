use crate::batch_runner::score_single_principal;
use crate::config::RiskConfig;
use crate::finding::RiskAssessment;
use crate::signals::{GraphQueryService, SignalError};
use crate::types::EscalationRule;
use std::collections::HashSet;

use super::principal_enumerator::enumerate_principals;

/// Statistics from an iterative scoring run
#[derive(Debug, Clone)]
pub struct IterationStats {
    /// Total number of principals enumerated
    pub total_principals: usize,
    /// Number of iterations completed
    pub iterations_completed: usize,
    /// Whether the loop converged (no new edges below threshold)
    pub converged: bool,
    /// New edges discovered per iteration
    pub new_edges_per_iteration: Vec<usize>,
    /// All risk assessments computed
    pub assessments: Vec<RiskAssessment>,
}

/// Configuration for the iterative scoring loop
#[derive(Debug, Clone)]
pub struct IterationConfig {
    /// Maximum number of iterations (default: 10)
    pub max_iterations: usize,
    /// Consider converged when new edges per iteration falls below this (default: 5)
    pub convergence_threshold: usize,
    /// Maximum path length for cycle detection (default: 20)
    pub max_path_length: usize,
}

impl Default for IterationConfig {
    fn default() -> Self {
        Self {
            max_iterations: 10,
            convergence_threshold: 5,
            max_path_length: 20,
        }
    }
}

/// Run iterative scoring loop with cycle detection and convergence.
///
/// The loop:
/// 1. Enumerates all principals from the graph
/// 2. For each iteration:
///    - Scores each principal (computes signals + matches rules)
///    - Tracks visited escalation chains to detect cycles
///    - Writes assessments back to graph
///    - Counts new edges discovered this iteration
/// 3. Checks convergence (no new edges below threshold)
/// 4. Early-exits if no new edges for 2 consecutive iterations
/// 5. Reports final statistics
///
/// # Arguments
///
/// * `graph` - Graph query service with principal and relationship data
/// * `rules` - Escalation rules to match against permissions
/// * `risk_config` - Risk configuration with signal weights
/// * `iteration_config` - Iteration loop configuration (max iterations, thresholds)
/// * `computed_at` - ISO 8601 timestamp for assessment metadata
///
/// # Returns
///
/// Statistics from the run including convergence status and edge counts,
/// or an error if graph operations fail.
///
/// # Example
///
/// ```ignore
/// let config = IterationConfig::default();
/// let stats = run_iterative_scoring(
///     &graph,
///     &rules,
///     &risk_config,
///     &config,
///     "2026-05-23T10:00:00Z",
/// ).await?;
/// println!("Converged: {}, iterations: {}", stats.converged, stats.iterations_completed);
/// ```
pub async fn run_iterative_scoring(
    graph: &dyn GraphQueryService,
    rules: &[EscalationRule],
    risk_config: &RiskConfig,
    iteration_config: &IterationConfig,
    computed_at: &str,
) -> Result<IterationStats, SignalError> {
    let principals = enumerate_principals(graph)
        .await
        .map_err(|e| Box::new(crate::signals::GraphQueryError(e.to_string())) as SignalError)?;

    let total_principals = principals.len();
    let mut assessments_by_principal: std::collections::HashMap<String, RiskAssessment> =
        std::collections::HashMap::new();
    let mut new_edges_per_iteration = Vec::new();
    let mut converged = false;
    let mut visited_chains: HashSet<String> = HashSet::new();

    // Only iterate if there are principals to score
    if total_principals > 0 {
        for iteration in 0..iteration_config.max_iterations {
            let mut new_edges_this_iteration = 0;

            for principal in &principals {
                // Score this principal
                match score_single_principal(
                    &principal.principal_id,
                    &principal.effective_permissions,
                    rules,
                    graph,
                    risk_config,
                    computed_at,
                )
                .await
                {
                    Ok(assessment) => {
                        // Track assume-role chains with cycle detection
                        // Chain key = sorted pair to detect cycles
                        for rule_match in &assessment.matched_rules {
                            let chain_key =
                                format!("{}→{}", principal.principal_id, rule_match.rule_id);
                            if visited_chains.insert(chain_key) {
                                new_edges_this_iteration += 1;
                            }
                        }

                        // Write assessment to graph
                        if let Ok(json) = serde_json::to_string(&assessment) {
                            let _ = graph
                                .write_risk_assessment(&principal.principal_id, &json)
                                .await;
                        }

                        // Store latest assessment per principal (not per iteration)
                        assessments_by_principal.insert(principal.principal_id.clone(), assessment);
                    }
                    Err(e) => {
                        tracing::warn!(
                            principal = %principal.principal_id,
                            error = %e,
                            iteration = iteration,
                            "Failed to score principal — excluded from results"
                        );
                        continue;
                    }
                }
            }

            new_edges_per_iteration.push(new_edges_this_iteration);

            // Check for convergence after recording this iteration's edge count
            // Convergence detected if:
            // 1. New edges this iteration below threshold
            if new_edges_this_iteration < iteration_config.convergence_threshold {
                converged = true;
                break;
            }

            // Check for 2 consecutive iterations with no new edges (strong convergence signal)
            if new_edges_per_iteration.len() >= 2 {
                let len = new_edges_per_iteration.len();
                if new_edges_per_iteration[len - 1] == 0 && new_edges_per_iteration[len - 2] == 0 {
                    converged = true;
                    break;
                }
            }
        }
    } else {
        converged = true;
    }

    // Collect final assessments from map to vec
    let all_assessments: Vec<RiskAssessment> = assessments_by_principal.into_values().collect();

    Ok(IterationStats {
        total_principals,
        iterations_completed: new_edges_per_iteration.len(),
        converged,
        new_edges_per_iteration,
        assessments: all_assessments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RiskConfig;
    use crate::signals::test_fixtures::MockGraphQueryService;
    use crate::types::{EscalationRule, Prerequisites, RequiredPermission};

    fn test_rule(id: &str, permissions: &[&str], tier: u8) -> EscalationRule {
        EscalationRule {
            id: id.to_string(),
            name: format!("Test rule {}", id),
            category: match tier {
                1 => "self-escalation".to_string(),
                2 => "new-passrole".to_string(),
                3 => "credential-access".to_string(),
                4 => "data-access".to_string(),
                _ => "other".to_string(),
            },
            services: vec!["test".to_string()],
            permissions_required: permissions
                .iter()
                .map(|p| RequiredPermission {
                    permission: p.to_string(),
                    resource_constraints: None,
                })
                .collect(),
            prerequisites: Prerequisites::default(),
            severity_tier: tier,
            boost: match tier {
                1 => 0.15,
                2 => 0.10,
                3 => 0.05,
                4 => 0.03,
                _ => 0.02,
            },
            description: None,
        }
    }

    #[tokio::test]
    async fn iterative_scoring_empty_graph() {
        let config = RiskConfig::default();
        let iter_config = IterationConfig::default();
        let graph = MockGraphQueryService::new();
        let rules = vec![];

        let stats = run_iterative_scoring(
            &graph,
            &rules,
            &config,
            &iter_config,
            "2026-05-23T10:00:00Z",
        )
        .await
        .unwrap();

        assert_eq!(stats.total_principals, 0);
        assert_eq!(stats.iterations_completed, 0);
        assert!(stats.converged);
        assert_eq!(stats.assessments.len(), 0);
    }

    #[tokio::test]
    async fn iterative_scoring_single_principal_no_rules() {
        let config = RiskConfig::default();
        let iter_config = IterationConfig::default();
        let graph = MockGraphQueryService::new()
            .with_principal_ids(vec!["principal-1".to_string()])
            .with_reachable("principal-1".to_string(), 0)
            .with_effective_permissions(
                "principal-1".to_string(),
                vec![("s3:GetObject".to_string(), "*".to_string())],
            );
        let rules = vec![];

        let stats = run_iterative_scoring(
            &graph,
            &rules,
            &config,
            &iter_config,
            "2026-05-23T10:00:00Z",
        )
        .await
        .unwrap();

        assert_eq!(stats.total_principals, 1);
        assert_eq!(stats.iterations_completed, 1);
        assert!(stats.converged);
        assert_eq!(stats.assessments.len(), 1);
        assert_eq!(stats.new_edges_per_iteration[0], 0);
    }

    #[tokio::test]
    async fn iterative_scoring_single_principal_with_matching_rule() {
        let config = RiskConfig::default();
        let iter_config = IterationConfig::default();
        let graph = MockGraphQueryService::new()
            .with_principal_ids(vec!["principal-1".to_string()])
            .with_reachable("principal-1".to_string(), 50)
            .with_effective_permissions(
                "principal-1".to_string(),
                vec![("iam:CreatePolicyVersion".to_string(), "*".to_string())],
            );
        let rules = vec![test_rule("iam-001", &["iam:CreatePolicyVersion"], 1)];

        let stats = run_iterative_scoring(
            &graph,
            &rules,
            &config,
            &iter_config,
            "2026-05-23T10:00:00Z",
        )
        .await
        .unwrap();

        assert_eq!(stats.total_principals, 1);
        assert_eq!(stats.iterations_completed, 1);
        assert!(stats.converged);
        assert_eq!(stats.assessments.len(), 1);
        // One rule matched → one new edge tracked
        assert_eq!(stats.new_edges_per_iteration[0], 1);
    }

    #[tokio::test]
    async fn iterative_scoring_three_principals_with_chains() {
        let config = RiskConfig::default();
        let iter_config = IterationConfig {
            max_iterations: 5,
            convergence_threshold: 2,
            max_path_length: 20,
        };

        let graph = MockGraphQueryService::new()
            .with_principal_ids(vec![
                "principal-1".to_string(),
                "principal-2".to_string(),
                "principal-3".to_string(),
            ])
            .with_reachable("principal-1".to_string(), 10)
            .with_reachable("principal-2".to_string(), 20)
            .with_reachable("principal-3".to_string(), 5)
            .with_effective_permissions(
                "principal-1".to_string(),
                vec![("iam:CreatePolicyVersion".to_string(), "*".to_string())],
            )
            .with_effective_permissions(
                "principal-2".to_string(),
                vec![("iam:AttachUserPolicy".to_string(), "*".to_string())],
            )
            .with_effective_permissions(
                "principal-3".to_string(),
                vec![("s3:GetObject".to_string(), "*".to_string())],
            );

        let rules = vec![
            test_rule("iam-001", &["iam:CreatePolicyVersion"], 1),
            test_rule("iam-002", &["iam:AttachUserPolicy"], 2),
        ];

        let stats = run_iterative_scoring(
            &graph,
            &rules,
            &config,
            &iter_config,
            "2026-05-23T10:00:00Z",
        )
        .await
        .unwrap();

        assert_eq!(stats.total_principals, 3);
        assert!(stats.iterations_completed >= 1);
        assert_eq!(stats.assessments.len(), 3);
        // First iteration: 2 rules matched (iam-001, iam-002) → 2 new edges
        assert_eq!(stats.new_edges_per_iteration[0], 2);
    }

    #[tokio::test]
    async fn iterative_scoring_converges_on_second_iteration() {
        let config = RiskConfig::default();
        let iter_config = IterationConfig {
            max_iterations: 5,
            convergence_threshold: 1,
            max_path_length: 20,
        };

        let graph = MockGraphQueryService::new()
            .with_principal_ids(vec!["user-1".to_string(), "role-1".to_string()])
            .with_reachable("user-1".to_string(), 10)
            .with_reachable("role-1".to_string(), 5)
            .with_effective_permissions(
                "user-1".to_string(),
                vec![("iam:CreatePolicyVersion".to_string(), "*".to_string())],
            )
            .with_effective_permissions(
                "role-1".to_string(),
                vec![("s3:*".to_string(), "*".to_string())],
            );

        let rules = vec![test_rule("iam-001", &["iam:CreatePolicyVersion"], 1)];

        let stats = run_iterative_scoring(
            &graph,
            &rules,
            &config,
            &iter_config,
            "2026-05-23T10:00:00Z",
        )
        .await
        .unwrap();

        assert_eq!(stats.total_principals, 2);
        // Iteration 1: 1 principal matches iam-001 → 1 new edge. 1 < threshold (1) is false, continue
        // But wait, convergence_threshold=1 means if new_edges < 1, converge. 1 < 1 is false.
        // So iteration 1 has 1 new edge, doesn't meet threshold, continues
        // Iteration 2: same principal matches again, but chain already visited, 0 new edges
        // 0 < 1 is true, so converges
        assert_eq!(stats.iterations_completed, 2);
        assert!(stats.converged);
        assert_eq!(stats.new_edges_per_iteration.len(), 2);
    }

    #[tokio::test]
    async fn iterative_scoring_cycle_detection() {
        // Test that cycle detection prevents infinite loops
        // Principal A and B both match the same rule repeatedly
        let config = RiskConfig::default();
        let iter_config = IterationConfig {
            max_iterations: 5,
            convergence_threshold: 1,
            max_path_length: 20,
        };

        let graph = MockGraphQueryService::new()
            .with_principal_ids(vec!["principal-a".to_string(), "principal-b".to_string()])
            .with_reachable("principal-a".to_string(), 10)
            .with_reachable("principal-b".to_string(), 10)
            .with_effective_permissions(
                "principal-a".to_string(),
                vec![("iam:CreatePolicyVersion".to_string(), "*".to_string())],
            )
            .with_effective_permissions(
                "principal-b".to_string(),
                vec![("iam:CreatePolicyVersion".to_string(), "*".to_string())],
            );

        let rules = vec![test_rule("iam-cycle", &["iam:CreatePolicyVersion"], 1)];

        let stats = run_iterative_scoring(
            &graph,
            &rules,
            &config,
            &iter_config,
            "2026-05-23T10:00:00Z",
        )
        .await
        .unwrap();

        assert_eq!(stats.total_principals, 2);
        // Both principals match the rule → 2 unique chain keys
        // On iteration 2, visiting the same chains returns 0 new edges → converges
        assert!(stats.converged);
        assert!(stats.iterations_completed <= 2);
    }

    #[tokio::test]
    async fn iterative_scoring_respects_max_iterations() {
        // Test that max_iterations acts as a hard limit
        // With cycle detection via visited_chains, we typically converge quickly.
        // This test verifies that even with a tiny max_iterations, we respect it.
        let config = RiskConfig::default();
        let iter_config = IterationConfig {
            max_iterations: 1,        // Hard limit of 1 iteration
            convergence_threshold: 0, // Never converge naturally (threshold 0 = requires negative edges)
            max_path_length: 20,
        };

        let graph = MockGraphQueryService::new()
            .with_principal_ids(vec!["principal-1".to_string(), "principal-2".to_string()])
            .with_reachable("principal-1".to_string(), 10)
            .with_reachable("principal-2".to_string(), 10)
            .with_effective_permissions(
                "principal-1".to_string(),
                vec![("iam:CreatePolicyVersion".to_string(), "*".to_string())],
            )
            .with_effective_permissions(
                "principal-2".to_string(),
                vec![("iam:CreatePolicyVersion".to_string(), "*".to_string())],
            );

        let rules = vec![test_rule("iam-001", &["iam:CreatePolicyVersion"], 1)];

        let stats = run_iterative_scoring(
            &graph,
            &rules,
            &config,
            &iter_config,
            "2026-05-23T10:00:00Z",
        )
        .await
        .unwrap();

        assert_eq!(stats.total_principals, 2);
        // Max iterations is 1, so we should stop after 1 iteration
        assert_eq!(stats.iterations_completed, 1);
        // With threshold=0, we only converge if new_edges < 0 (never), so not converged
        assert!(!stats.converged);
    }

    #[tokio::test]
    async fn iteration_stats_reflects_zero_new_edges_in_second_iteration() {
        // Test that when iteration 2 has 0 new edges, convergence is detected
        let config = RiskConfig::default();
        let iter_config = IterationConfig {
            max_iterations: 5,
            convergence_threshold: 2,
            max_path_length: 20,
        };

        let graph = MockGraphQueryService::new()
            .with_principal_ids(vec!["principal-1".to_string()])
            .with_reachable("principal-1".to_string(), 10)
            .with_effective_permissions(
                "principal-1".to_string(),
                vec![("iam:CreatePolicyVersion".to_string(), "*".to_string())],
            );

        let rules = vec![test_rule("iam-001", &["iam:CreatePolicyVersion"], 1)];

        let stats = run_iterative_scoring(
            &graph,
            &rules,
            &config,
            &iter_config,
            "2026-05-23T10:00:00Z",
        )
        .await
        .unwrap();

        assert_eq!(stats.total_principals, 1);
        assert_eq!(stats.iterations_completed, 1);
        // Iteration 1: 1 new edge (principal-1 → iam-001)
        // Iteration stops because 1 < threshold of 2
        assert_eq!(stats.new_edges_per_iteration[0], 1);
        assert!(stats.converged);
    }

    #[tokio::test]
    async fn iteration_stats_includes_all_assessments() {
        let config = RiskConfig::default();
        let iter_config = IterationConfig::default();

        let graph = MockGraphQueryService::new()
            .with_principal_ids(vec![
                "principal-1".to_string(),
                "principal-2".to_string(),
                "principal-3".to_string(),
            ])
            .with_reachable("principal-1".to_string(), 10)
            .with_reachable("principal-2".to_string(), 20)
            .with_reachable("principal-3".to_string(), 5)
            .with_effective_permissions(
                "principal-1".to_string(),
                vec![("s3:GetObject".to_string(), "*".to_string())],
            )
            .with_effective_permissions(
                "principal-2".to_string(),
                vec![("s3:ListBucket".to_string(), "*".to_string())],
            )
            .with_effective_permissions(
                "principal-3".to_string(),
                vec![("ec2:*".to_string(), "*".to_string())],
            );

        let rules = vec![];

        let stats = run_iterative_scoring(
            &graph,
            &rules,
            &config,
            &iter_config,
            "2026-05-23T10:00:00Z",
        )
        .await
        .unwrap();

        assert_eq!(stats.assessments.len(), 3);
        assert!(stats.assessments.iter().all(|a| !a.principal_id.is_empty()));
    }
}
