pub mod batch_runner;
pub mod config;
pub mod finding;
pub mod rule_engine;
pub mod rule_loader;
pub mod scorer;
pub mod signals;
pub mod stale_checker;
pub mod types;

pub use batch_runner::{batch_score_all, score_single_principal, BatchResult};
pub use config::{load_risk_config, validate_signal_weights, RiskConfig, SeverityThresholds};
pub use finding::{severity_from_score, RiskAssessment, Severity, SignalContribution};
pub use rule_engine::{compute_rule_boost, match_all_rules, match_rule, EffectivePermission};
pub use rule_loader::{load_rules_from_dir, parse_rule};
pub use scorer::score_principal;
pub use signals::{
    BlastRadiusSignal, CrossAccountHopsSignal, DangerousActionCountSignal, GraphQueryService,
    PathToAdminSignal, PermissionSurfaceSignal, SignalError, SignalResult,
};
pub use stale_checker::{is_stale, is_stale_option};
pub use types::{EscalationRule, MatchedRule, Prerequisites, RequiredPermission, RuleError};
