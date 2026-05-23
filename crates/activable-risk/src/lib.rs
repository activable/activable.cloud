pub mod rule_engine;
pub mod rule_loader;
pub mod signals;
pub mod types;

pub use rule_engine::{compute_rule_boost, match_all_rules, match_rule, EffectivePermission};
pub use rule_loader::{load_rules_from_dir, parse_rule};
pub use signals::{
    BlastRadiusSignal, CrossAccountHopsSignal, DangerousActionCountSignal, GraphQueryService,
    PathToAdminSignal, PermissionSurfaceSignal, SignalError, SignalResult,
};
pub use types::{EscalationRule, MatchedRule, Prerequisites, RequiredPermission, RuleError};
