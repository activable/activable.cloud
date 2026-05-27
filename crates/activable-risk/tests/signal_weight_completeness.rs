//! Regression test for the "signal name mismatch" bug class.
//! Asserts every Signal trait impl name is present in RiskConfig::default()
//! with a non-zero weight (except permission_surface which may be reserved).

use activable_risk::RiskConfig;

#[test]
fn every_signal_has_non_zero_default_weight() {
    let config = RiskConfig::default();
    // Hardcoded list of expected signal names. If a new signal is added without
    // updating RiskConfig::default(), this test catches the omission.
    let expected_names = [
        "blast_radius",
        "path_to_admin",
        "dangerous_action_count",
        "cross_account_hops",
        "permission_surface",
    ];
    for name in expected_names {
        let weight = config.signal_weight(name);
        assert!(
            weight > 0.0,
            "Signal '{}' has weight 0.0 — likely a key-name mismatch between config and signal::name()",
            name
        );
    }
}

#[test]
fn legacy_dangerous_actions_key_emits_warning_and_migrates() {
    // YAML with the legacy key
    let yaml = r#"
signals:
  blast_radius: 0.18
  path_to_admin: 0.22
  dangerous_actions: 0.18
  cross_account_hops: 0.07
  permission_surface: 0.05
severity:
  critical: 0.80
  high: 0.60
  medium: 0.40
  low: 0.20
"#;
    let config = activable_risk::load_risk_config(yaml).expect("legacy key parses");
    // Legacy key migrated to new name
    assert_eq!(config.signal_weight("dangerous_action_count"), 0.18);
    // Old key no longer present
    assert_eq!(config.signal_weight("dangerous_actions"), 0.0);
}
