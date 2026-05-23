use serde::{Deserialize, Serialize};

/// An escalation rule from pathfinding.cloud YAML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRule {
    pub id: String,
    pub name: String,
    pub category: String,
    pub services: Vec<String>,
    pub permissions_required: Vec<RequiredPermission>,
    #[serde(default)]
    pub prerequisites: Prerequisites,
    pub severity_tier: u8,
    pub boost: f64,
    #[serde(skip)]
    pub description: Option<String>,
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
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            RuleError::LoadError(msg) => write!(f, "Load error: {}", msg),
            RuleError::InvalidCategory(cat) => write!(f, "Invalid category: {}", cat),
        }
    }
}

impl std::error::Error for RuleError {}
