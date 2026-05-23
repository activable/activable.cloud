pub mod rule_engine;
pub mod rule_loader;
pub mod types;

pub use rule_engine::{compute_rule_boost, match_all_rules, match_rule, EffectivePermission};
pub use rule_loader::{load_rules_from_dir, parse_rule};
pub use types::{EscalationRule, MatchedRule, Prerequisites, RequiredPermission, RuleError};
