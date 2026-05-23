//! GraphQL type wrappers for risk assessment data structures.

use async_graphql::{Enum, SimpleObject};

/// Severity level of a risk assessment
#[derive(Enum, Copy, Clone, Debug, Eq, PartialEq)]
pub enum GqlSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<activable_risk::Severity> for GqlSeverity {
    fn from(s: activable_risk::Severity) -> Self {
        match s {
            activable_risk::Severity::Critical => GqlSeverity::Critical,
            activable_risk::Severity::High => GqlSeverity::High,
            activable_risk::Severity::Medium => GqlSeverity::Medium,
            activable_risk::Severity::Low => GqlSeverity::Low,
            activable_risk::Severity::Info => GqlSeverity::Info,
        }
    }
}

/// Contribution of a single risk signal to the overall score
#[derive(SimpleObject, Clone, Debug)]
pub struct GqlSignalContribution {
    pub name: String,
    pub raw_value: f64,
    pub normalized: f64,
    pub weight: f64,
    pub contribution: f64,
}

impl From<activable_risk::finding::SignalContribution> for GqlSignalContribution {
    fn from(s: activable_risk::finding::SignalContribution) -> Self {
        GqlSignalContribution {
            name: s.name,
            raw_value: s.raw_value,
            normalized: s.normalized,
            weight: s.weight,
            contribution: s.contribution,
        }
    }
}

/// A matched risk rule against a principal's permissions
#[derive(SimpleObject, Clone, Debug)]
pub struct GqlMatchedRule {
    pub rule_id: String,
    pub rule_name: String,
    pub category: String,
    pub severity_tier: i32, // safe: u8 ∈ [0, 255] ⊂ i32
    pub boost: f64,
    pub matched_permissions: Vec<String>,
}

impl From<activable_risk::types::MatchedRule> for GqlMatchedRule {
    fn from(r: activable_risk::types::MatchedRule) -> Self {
        GqlMatchedRule {
            rule_id: r.rule_id,
            rule_name: r.rule_name,
            category: r.category,
            severity_tier: r.severity_tier as i32,
            boost: r.boost,
            matched_permissions: r.matched_permissions,
        }
    }
}

/// Complete risk assessment for a principal
#[derive(SimpleObject, Clone, Debug)]
pub struct GqlRiskAssessment {
    pub principal_id: String,
    pub score: f64,
    pub severity: GqlSeverity,
    pub signals: Vec<GqlSignalContribution>,
    pub matched_rules: Vec<GqlMatchedRule>,
    pub rule_boost: f64,
    pub signal_total: f64,
    pub computed_at: String,
}

impl From<activable_risk::finding::RiskAssessment> for GqlRiskAssessment {
    fn from(a: activable_risk::finding::RiskAssessment) -> Self {
        GqlRiskAssessment {
            principal_id: a.principal_id,
            score: a.score,
            severity: GqlSeverity::from(a.severity),
            signals: a
                .signal_contributions
                .into_iter()
                .map(GqlSignalContribution::from)
                .collect(),
            matched_rules: a
                .matched_rules
                .into_iter()
                .map(GqlMatchedRule::from)
                .collect(),
            rule_boost: a.rule_boost,
            signal_total: a.signal_total,
            computed_at: a.computed_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_maps_critical() {
        let severity = GqlSeverity::from(activable_risk::Severity::Critical);
        assert_eq!(severity, GqlSeverity::Critical);
    }

    #[test]
    fn severity_maps_high() {
        let severity = GqlSeverity::from(activable_risk::Severity::High);
        assert_eq!(severity, GqlSeverity::High);
    }

    #[test]
    fn severity_maps_medium() {
        let severity = GqlSeverity::from(activable_risk::Severity::Medium);
        assert_eq!(severity, GqlSeverity::Medium);
    }

    #[test]
    fn severity_maps_low() {
        let severity = GqlSeverity::from(activable_risk::Severity::Low);
        assert_eq!(severity, GqlSeverity::Low);
    }

    #[test]
    fn severity_maps_info() {
        let severity = GqlSeverity::from(activable_risk::Severity::Info);
        assert_eq!(severity, GqlSeverity::Info);
    }

    #[test]
    fn signal_contribution_converts() {
        let signal = activable_risk::finding::SignalContribution {
            name: "blast_radius".to_string(),
            raw_value: 50.0,
            normalized: 0.5,
            weight: 0.2,
            contribution: 0.1,
        };
        let gql_signal = GqlSignalContribution::from(signal);
        assert_eq!(gql_signal.name, "blast_radius");
        assert_eq!(gql_signal.raw_value, 50.0);
        assert_eq!(gql_signal.normalized, 0.5);
        assert_eq!(gql_signal.weight, 0.2);
        assert_eq!(gql_signal.contribution, 0.1);
    }

    #[test]
    fn matched_rule_converts() {
        let rule = activable_risk::types::MatchedRule {
            rule_id: "r-123".to_string(),
            rule_name: "AssumeRole".to_string(),
            category: "lateral_movement".to_string(),
            severity_tier: 2,
            boost: 0.15,
            matched_permissions: vec!["sts:AssumeRole".to_string()],
        };
        let gql_rule = GqlMatchedRule::from(rule);
        assert_eq!(gql_rule.rule_id, "r-123");
        assert_eq!(gql_rule.rule_name, "AssumeRole");
        assert_eq!(gql_rule.severity_tier, 2);
        assert_eq!(gql_rule.boost, 0.15);
    }

    #[test]
    fn risk_assessment_converts() {
        let assessment = activable_risk::finding::RiskAssessment {
            principal_id: "arn:aws:iam::123456789012:user/alice".to_string(),
            score: 0.72,
            severity: activable_risk::Severity::High,
            signal_contributions: vec![activable_risk::finding::SignalContribution {
                name: "blast_radius".to_string(),
                raw_value: 50.0,
                normalized: 0.5,
                weight: 0.2,
                contribution: 0.1,
            }],
            matched_rules: vec![],
            rule_boost: 0.0,
            signal_total: 0.72,
            computed_at: "2026-05-23T10:00:00Z".to_string(),
        };
        let gql = GqlRiskAssessment::from(assessment);
        assert_eq!(gql.principal_id, "arn:aws:iam::123456789012:user/alice");
        assert_eq!(gql.score, 0.72);
        assert_eq!(gql.severity, GqlSeverity::High);
        assert_eq!(gql.signals.len(), 1);
        assert_eq!(gql.signal_total, 0.72);
    }
}
