use crate::config::RiskConfig;
use crate::finding::{RiskAssessment, Severity, SignalContribution};
use crate::signals::SignalResult;
use crate::types::MatchedRule;

/// Score a principal by combining signal results and matched rules.
///
/// Scoring formula:
/// 1. Compute signal contribution: Σ(weight_i × normalized_i)
/// 2. Compute rule boost: already capped at 0.30 by rule_engine
/// 3. Final score: clamp(signal_contribution + rule_boost, 0.0, 1.0)
/// 4. Derive severity from final score
pub fn score_principal(
    principal_id: &str,
    signal_results: Vec<SignalResult>,
    matched_rules: Vec<MatchedRule>,
    config: &RiskConfig,
    computed_at: &str, // ISO 8601 timestamp
) -> RiskAssessment {
    // Compute signal contribution and build detailed records
    let mut signal_contributions = Vec::new();
    let mut signal_total = 0.0;

    for signal in signal_results {
        let weight = config.signal_weight(signal.name);
        let contribution = signal.normalized * weight;
        signal_total += contribution;

        signal_contributions.push(SignalContribution {
            name: signal.name.to_string(),
            raw_value: signal.raw_value,
            normalized: signal.normalized,
            weight,
            contribution,
        });
    }

    // Sum rule boosts (each rule's boost is uncapped; total is capped at 0.30)
    let rule_boost: f64 = matched_rules.iter().map(|m| m.boost).sum();
    let rule_boost = rule_boost.min(0.30); // Enforce global cap

    // Final score: signal contribution + rule boost, clamped to [0.0, 1.0]
    let score = (signal_total + rule_boost).clamp(0.0, 1.0);

    // Derive severity
    let severity = Severity::from_score(score, &config.severity);

    RiskAssessment {
        principal_id: principal_id.to_string(),
        score,
        severity,
        signal_contributions,
        matched_rules,
        rule_boost,
        signal_total,
        computed_at: computed_at.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(name: &'static str, raw_value: f64, normalized: f64, weight: f64) -> SignalResult {
        SignalResult::new(name, raw_value, normalized, weight)
    }

    fn matched_rule(id: &str, tier: u8, boost: f64) -> MatchedRule {
        MatchedRule {
            rule_id: id.to_string(),
            rule_name: format!("Rule {}", id),
            category: "test".to_string(),
            severity_tier: tier,
            boost,
            matched_permissions: vec!["s3:*".to_string()],
        }
    }

    #[test]
    fn score_with_all_signals_and_rules() {
        let config = RiskConfig::default();
        let signals = vec![
            signal("blast_radius", 0.72, 0.72, 0.18), // contribution: 0.1296
            signal("path_to_admin", 0.75, 0.75, 0.22), // contribution: 0.165
            signal("dangerous_action_count", 0.60, 0.60, 0.18), // contribution: 0.108
            signal("cross_account_hops", 0.40, 0.40, 0.07), // contribution: 0.028
        ];
        let rules = vec![
            matched_rule("iam-001", 1, 0.15),
            matched_rule("ec2-001", 2, 0.10),
        ];
        let assessment = score_principal(
            "principal-1",
            signals,
            rules,
            &config,
            "2026-05-23T10:00:00Z",
        );

        // signal_contribution = 0.1296 + 0.165 + 0.108 + 0.028 = 0.4306
        // rule_boost = 0.15 + 0.10 = 0.25
        // total = 0.6806
        assert!((assessment.score - 0.6806).abs() < 0.01);
        assert_eq!(assessment.severity, Severity::High);
        assert_eq!(assessment.signal_contributions.len(), 4);
        assert_eq!(assessment.matched_rules.len(), 2);
    }

    #[test]
    fn score_zero_risk() {
        let config = RiskConfig::default();
        let signals = vec![
            signal("blast_radius", 0.0, 0.0, 0.18),
            signal("path_to_admin", 0.0, 0.0, 0.22),
            signal("dangerous_action_count", 0.0, 0.0, 0.18),
            signal("cross_account_hops", 0.0, 0.0, 0.07),
        ];
        let assessment = score_principal(
            "principal-2",
            signals,
            vec![],
            &config,
            "2026-05-23T10:00:00Z",
        );

        assert_eq!(assessment.score, 0.0);
        assert_eq!(assessment.severity, Severity::Info);
        assert_eq!(assessment.signal_total, 0.0);
        assert_eq!(assessment.rule_boost, 0.0);
    }

    #[test]
    fn score_max_risk() {
        let config = RiskConfig::default();
        let signals = vec![
            signal("blast_radius", 1.0, 1.0, 0.18),
            signal("path_to_admin", 1.0, 1.0, 0.22),
            signal("dangerous_action_count", 1.0, 1.0, 0.18),
            signal("cross_account_hops", 1.0, 1.0, 0.07),
        ];
        let rules = vec![
            matched_rule("iam-001", 1, 0.15),
            matched_rule("iam-002", 1, 0.15),
            matched_rule("iam-003", 1, 0.15), // boost capped at 0.30
        ];
        let assessment = score_principal(
            "principal-3",
            signals,
            rules,
            &config,
            "2026-05-23T10:00:00Z",
        );

        // signal_contribution = 0.18 + 0.22 + 0.18 + 0.07 = 0.65
        // rule_boost = 0.15 + 0.15 + 0.15 = 0.45, capped at 0.30
        // total = 0.65 + 0.30 = 0.95
        assert!((assessment.score - 0.95).abs() < 0.01);
        assert_eq!(assessment.severity, Severity::Critical);
        assert!((assessment.signal_total - 0.65).abs() < 0.01);
        assert_eq!(assessment.rule_boost, 0.30);
    }

    #[test]
    fn rule_boost_capped_at_030() {
        let config = RiskConfig::default();
        let signals = vec![signal("blast_radius", 0.0, 0.0, 0.20)];
        let rules = vec![
            matched_rule("iam-001", 1, 0.20),
            matched_rule("iam-002", 1, 0.20),
            matched_rule("iam-003", 1, 0.20),
        ];
        let assessment = score_principal(
            "principal-4",
            signals,
            rules,
            &config,
            "2026-05-23T10:00:00Z",
        );

        // Uncapped sum would be 0.60, but capped at 0.30
        assert_eq!(assessment.rule_boost, 0.30);
        assert!((assessment.score - 0.30).abs() < 0.001);
    }

    #[test]
    fn signal_contributions_calculated_correctly() {
        let config = RiskConfig::default();
        let signals = vec![signal("blast_radius", 0.5, 0.5, 0.18)];
        let assessment = score_principal(
            "principal-5",
            signals,
            vec![],
            &config,
            "2026-05-23T10:00:00Z",
        );

        assert_eq!(assessment.signal_contributions.len(), 1);
        let contrib = &assessment.signal_contributions[0];
        assert_eq!(contrib.name, "blast_radius");
        assert_eq!(contrib.normalized, 0.5);
        assert_eq!(contrib.weight, 0.18);
        assert_eq!(contrib.contribution, 0.09);
    }

    #[test]
    fn missing_signals_default_to_zero_weight() {
        let config = RiskConfig::default();
        // Use a signal name not in config
        let signals = vec![signal("nonexistent", 0.5, 0.5, 0.0)];
        let assessment = score_principal(
            "principal-6",
            signals,
            vec![],
            &config,
            "2026-05-23T10:00:00Z",
        );

        // Signal weight should be looked up from config, which returns 0.0 for missing
        assert_eq!(assessment.signal_total, 0.0);
    }
}
