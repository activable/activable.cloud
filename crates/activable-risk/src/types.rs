use serde::{Deserialize, Serialize};

/// A rule requirement — single permission or combinator tree (max depth 2).
/// Serde's `untagged` allows flexible YAML:
/// - bare `permission: "iam:PassRole"` → Single variant
/// - `all_of: [...]` → AllOf variant
/// - `any_of: [...]` → AnyOf variant
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RuleRequirement {
    /// Single (action, optional resource_pattern) requirement.
    Single(RequiredPermission),
    /// All listed sub-requirements must match.
    AllOf { all_of: Vec<RuleRequirement> },
    /// Any one of the sub-requirements suffices.
    AnyOf { any_of: Vec<RuleRequirement> },
}

impl RuleRequirement {
    /// Validate that this requirement tree does not exceed depth 2.
    /// Returns error if depth > 2.
    pub fn validate_depth(&self) -> Result<(), String> {
        self.check_depth(0)
    }

    fn check_depth(&self, current_depth: usize) -> Result<(), String> {
        if current_depth > 2 {
            return Err("rule requirement tree exceeds max depth 2 — flatten".to_string());
        }
        match self {
            RuleRequirement::Single(_) => Ok(()),
            RuleRequirement::AllOf { all_of } => {
                for req in all_of {
                    req.check_depth(current_depth + 1)?;
                }
                Ok(())
            }
            RuleRequirement::AnyOf { any_of } => {
                for req in any_of {
                    req.check_depth(current_depth + 1)?;
                }
                Ok(())
            }
        }
    }
}

/// An escalation rule from pathfinding.cloud YAML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRule {
    pub id: String,
    pub name: String,
    pub category: String,
    pub services: Vec<String>,
    #[serde(default)]
    pub permissions: Option<RuleRequirement>,
    #[serde(default)]
    pub prerequisites: Prerequisites,
    pub severity_tier: u8,
    pub boost: f64,
    #[serde(default)]
    pub trigger: Option<CascadeTrigger>,
    #[serde(skip)]
    pub description: Option<String>,
}

/// Trigger condition for cascade rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CascadeTrigger {
    pub match_count: u32,
    pub min_tier: u8,
    #[serde(default)]
    pub scope: CascadeScope,
}

/// Scope for cascade rule evaluation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum CascadeScope {
    /// Cascade fires when N primary rules match on the same principal.
    #[default]
    Principal,
    /// Cascade fires when N primary rules match in the same account.
    Account,
}

/// A required permission for an escalation rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredPermission {
    pub permission: String,
    #[serde(rename = "resourceConstraints")]
    pub resource_constraints: Option<String>,
}

/// Prerequisites for an escalation rule (uniform or tabbed)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Prerequisites {
    Uniform(Vec<String>),
    Tabbed {
        admin: Vec<String>,
        lateral: Vec<String>,
    },
}

impl Default for Prerequisites {
    fn default() -> Self {
        Prerequisites::Uniform(Vec::new())
    }
}

/// A matched rule against a principal's permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRule {
    pub rule_id: String,
    pub rule_name: String,
    pub category: String,
    pub severity_tier: u8,
    pub boost: f64,
    pub matched_permissions: Vec<String>,
}

/// Error types for rule loading and matching
#[derive(Debug)]
pub enum RuleError {
    ParseError(String),
    LoadError(String),
    InvalidCategory(String),
    DepthExceeded(String),
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            RuleError::LoadError(msg) => write!(f, "Load error: {}", msg),
            RuleError::InvalidCategory(cat) => write!(f, "Invalid category: {}", cat),
            RuleError::DepthExceeded(msg) => write!(f, "Depth exceeded: {}", msg),
        }
    }
}

impl std::error::Error for RuleError {}
