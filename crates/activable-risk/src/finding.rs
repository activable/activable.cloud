use crate::config::SeverityThresholds;
use crate::types::MatchedRule;
use serde::{Deserialize, Serialize};

/// Severity level of a risk assessment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    /// Derive severity from a risk score based on thresholds
    pub fn from_score(score: f64, thresholds: &SeverityThresholds) -> Self {
        if score >= thresholds.critical {
            Severity::Critical
        } else if score >= thresholds.high {
            Severity::High
        } else if score >= thresholds.medium {
            Severity::Medium
        } else if score >= thresholds.low {
            Severity::Low
        } else {
            Severity::Info
        }
    }
}

/// Convenience function: derive severity from a risk score using default thresholds
pub fn severity_from_score(score: f64) -> Severity {
    let thresholds = SeverityThresholds {
        critical: 0.80,
        high: 0.60,
        medium: 0.40,
        low: 0.20,
    };
    Severity::from_score(score, &thresholds)
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "Critical"),
            Severity::High => write!(f, "High"),
            Severity::Medium => write!(f, "Medium"),
            Severity::Low => write!(f, "Low"),
            Severity::Info => write!(f, "Info"),
        }
    }
}

/// Contribution of a single risk signal to the overall score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalContribution {
    pub name: String,
    pub raw_value: f64,
    pub normalized: f64,
    pub weight: f64,
    pub contribution: f64, // normalized × weight
}

/// Complete risk assessment for a principal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub principal_id: String,
    pub score: f64,
    pub severity: Severity,
    pub signal_contributions: Vec<SignalContribution>,
    pub matched_rules: Vec<MatchedRule>,
    pub rule_boost: f64,
    pub signal_total: f64,
    pub computed_at: String, // ISO 8601 timestamp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_critical_at_080() {
        let thresholds = SeverityThresholds {
            critical: 0.80,
            high: 0.60,
            medium: 0.40,
            low: 0.20,
        };
        assert_eq!(Severity::from_score(0.80, &thresholds), Severity::Critical);
    }

    #[test]
    fn severity_high_at_060() {
        let thresholds = SeverityThresholds {
            critical: 0.80,
            high: 0.60,
            medium: 0.40,
            low: 0.20,
        };
        assert_eq!(Severity::from_score(0.60, &thresholds), Severity::High);
    }

    #[test]
    fn severity_medium_at_040() {
        let thresholds = SeverityThresholds {
            critical: 0.80,
            high: 0.60,
            medium: 0.40,
            low: 0.20,
        };
        assert_eq!(Severity::from_score(0.40, &thresholds), Severity::Medium);
    }

    #[test]
    fn severity_low_at_020() {
        let thresholds = SeverityThresholds {
            critical: 0.80,
            high: 0.60,
            medium: 0.40,
            low: 0.20,
        };
        assert_eq!(Severity::from_score(0.20, &thresholds), Severity::Low);
    }

    #[test]
    fn severity_info_below_020() {
        let thresholds = SeverityThresholds {
            critical: 0.80,
            high: 0.60,
            medium: 0.40,
            low: 0.20,
        };
        assert_eq!(Severity::from_score(0.19, &thresholds), Severity::Info);
    }

    #[test]
    fn severity_info_at_zero() {
        let thresholds = SeverityThresholds {
            critical: 0.80,
            high: 0.60,
            medium: 0.40,
            low: 0.20,
        };
        assert_eq!(Severity::from_score(0.0, &thresholds), Severity::Info);
    }
}
