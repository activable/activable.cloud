pub mod batch_runner;
pub mod config;
pub mod enumeration;
pub mod finding;
pub mod fuzzing;
pub mod rule_engine;
pub mod rule_loader;
pub mod scorer;
pub mod service_catalog;
pub mod signals;
pub mod stale_checker;
pub mod types;

pub use batch_runner::{batch_score_all, score_single_principal, BatchResult};
pub use config::{load_risk_config, validate_signal_weights, RiskConfig, SeverityThresholds};
pub use enumeration::{
    enumerate_principals, run_iterative_scoring, EnumeratedPrincipal, IterationConfig,
    IterationStats,
};
pub use finding::{severity_from_score, RiskAssessment, Severity, SignalContribution};
pub use fuzzing::{
    generate_pairs, generate_triples, run_fuzzer, FuzzConfig, FuzzDiscovery, FuzzSeverity,
};
pub use rule_engine::{compute_rule_boost, match_all_rules, match_rule, EffectivePermission};
pub use rule_loader::{load_rules_from_dir, load_rules_from_embedded, parse_rule};
pub use scorer::score_principal;
pub use service_catalog::{
    assess_expansion_impact, builtin_catalog, compute_expansion_score, create_snapshot,
    diff_catalogs, ActionCatalogSnapshot, CatalogDiff, ExpansionImpact, ExpansionSeverity,
};
pub use signals::{
    BlastRadiusSignal, CrossAccountHopsSignal, DangerousActionCountSignal, GraphQueryService,
    PathToAdminSignal, PermissionSurfaceSignal, SignalError, SignalResult,
};
pub use stale_checker::{is_stale, is_stale_option};
pub use types::{EscalationRule, MatchedRule, Prerequisites, RequiredPermission, RuleError};
