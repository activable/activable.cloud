pub mod batch_runner;
pub mod cascade;
pub mod config;
pub mod enumeration;
pub mod finding;
pub mod fuzzing;
pub mod rule_engine;
pub mod rule_loader;
pub mod scorer;
pub mod service_catalog;
pub mod services;
pub mod signals;
pub mod stale_checker;
pub mod types;

pub use batch_runner::{batch_score_all, score_single_principal, BatchResult};
pub use cascade::harmonic_mean;
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
pub use services::{
    assess_account_risk, assess_federation_risk, assess_key_management_risk,
    assess_resource_policy_risk, categorize_rule, compute_grant_severity, compute_key_risk_score,
    compute_resource_policy_score, evaluate_oidc_weakness, evaluate_trust_boundary,
    extract_account_from_key_arn,
    extract_account_id_from_principal_arn as extract_account_id_from_arn,
    extract_resource_account_id_from_arn, normalize_key_id, parse_key_policy,
    parse_resource_policy, AccountCategorySignals, AccountRiskResult, CategorySignal,
    CreateGrantRisk, CrossAccountAccess, EvaluatedOidcProvider, FederationRiskResult,
    KeyManagementRiskResult, KeyPolicy, KeyPolicyStatement, KeyRiskError, KeyRiskSeverity,
    PrincipalRiskSummary, ResourcePolicy, ResourcePolicyError, ResourcePolicyRiskResult,
    ResourcePolicySeverity, ResourcePolicyStatement, RiskSeverity,
};
pub use signals::{
    BlastRadiusSignal, CrossAccountHopsSignal, DangerousActionCountSignal, GraphQueryService,
    PathToAdminSignal, PermissionSurfaceSignal, SignalError, SignalResult,
};
pub use stale_checker::{is_stale, is_stale_option};
pub use types::{EscalationRule, MatchedRule, Prerequisites, RequiredPermission, RuleError};
