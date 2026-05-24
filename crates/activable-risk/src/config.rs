use serde::{Deserialize, Deserializer};
use std::collections::HashMap;

/// Risk configuration with signal weights and severity thresholds
#[derive(Debug, Clone)]
pub struct RiskConfig {
    pub signals: HashMap<String, f64>,
    pub severity: SeverityThresholds,
}

impl<'de> Deserialize<'de> for RiskConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawConfig {
            signals: HashMap<String, f64>,
            severity: SeverityThresholds,
        }

        let mut raw = RawConfig::deserialize(deserializer)?;

        // Migrate legacy "dangerous_actions" key to "dangerous_action_count"
        if let Some(value) = raw.signals.remove("dangerous_actions") {
            tracing::warn!(
                legacy_key = "dangerous_actions",
                suggested = "dangerous_action_count",
                "deprecated config key, use new name"
            );
            raw.signals.insert("dangerous_action_count".to_string(), value);
        }

        Ok(RiskConfig {
            signals: raw.signals,
            severity: raw.severity,
        })
    }
}

/// Severity threshold configuration
#[derive(Debug, Clone, Deserialize)]
pub struct SeverityThresholds {
    pub critical: f64,
    pub high: f64,
    pub medium: f64,
    pub low: f64,
}

impl RiskConfig {
    /// Get signal weight, defaulting to 0.0 if not present
    pub fn signal_weight(&self, name: &str) -> f64 {
        self.signals.get(name).copied().unwrap_or(0.0)
    }
}

impl RiskConfig {
    /// Sum of all signal weights
    pub fn signals_weight_sum(&self) -> f64 {
        self.signals.values().sum()
    }
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            signals: vec![
                ("blast_radius".to_string(), 0.18),
                ("path_to_admin".to_string(), 0.22),
                ("dangerous_action_count".to_string(), 0.18),
                ("cross_account_hops".to_string(), 0.07),
                ("permission_surface".to_string(), 0.05),
            ]
            .into_iter()
            .collect(),
            severity: SeverityThresholds {
                critical: 0.80,
                high: 0.60,
                medium: 0.40,
                low: 0.20,
            },
        }
    }
}

/// Load risk configuration from YAML content
pub fn load_risk_config(yaml_content: &str) -> Result<RiskConfig, serde_yaml::Error> {
    serde_yaml::from_str(yaml_content)
}

/// Validate that signal weights sum to <= 0.70
pub fn validate_signal_weights(config: &RiskConfig) -> Result<(), String> {
    let sum: f64 = config.signals.values().sum();
    if (sum - 0.70).abs() > 0.001 {
        return Err(format!("Signal weights sum to {:.4}, expected ~0.70", sum));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_correct_weights() {
        let config = RiskConfig::default();
        assert_eq!(config.signal_weight("blast_radius"), 0.18);
        assert_eq!(config.signal_weight("path_to_admin"), 0.22);
        assert_eq!(config.signal_weight("dangerous_action_count"), 0.18);
        assert_eq!(config.signal_weight("cross_account_hops"), 0.07);
        assert_eq!(config.signal_weight("permission_surface"), 0.05);
    }

    #[test]
    fn default_weights_sum_to_070() {
        let config = RiskConfig::default();
        validate_signal_weights(&config).unwrap();
    }

    #[test]
    fn default_severity_thresholds_are_correct() {
        let config = RiskConfig::default();
        assert_eq!(config.severity.critical, 0.80);
        assert_eq!(config.severity.high, 0.60);
        assert_eq!(config.severity.medium, 0.40);
        assert_eq!(config.severity.low, 0.20);
    }

    #[test]
    fn signal_weight_defaults_to_zero_for_missing() {
        let config = RiskConfig::default();
        assert_eq!(config.signal_weight("nonexistent"), 0.0);
    }

    #[test]
    fn load_default_weights_from_yaml() {
        let yaml = include_str!("../config/risk-weights.yaml");
        let config = load_risk_config(yaml).unwrap();
        assert_eq!(config.signal_weight("blast_radius"), 0.18);
        assert_eq!(config.signal_weight("path_to_admin"), 0.22);
    }

    #[test]
    fn yaml_weights_sum_to_070() {
        let yaml = include_str!("../config/risk-weights.yaml");
        let config = load_risk_config(yaml).unwrap();
        validate_signal_weights(&config).unwrap();
    }
}
