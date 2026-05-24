use crate::types::{EscalationRule, Prerequisites, RequiredPermission, RuleError};
use serde::{Deserialize, Serialize};
use std::path::Path;
use include_dir::{include_dir, Dir};

/// Intermediate YAML deserialization structure
#[derive(Debug, Deserialize, Serialize)]
struct YamlRule {
    id: String,
    name: String,
    category: String,
    services: Vec<String>,
    #[serde(default)]
    permissions: PermissionsContainer,
    #[serde(default)]
    prerequisites: Prerequisites,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct PermissionsContainer {
    #[serde(default)]
    required: Vec<RequiredPermission>,
}

/// Embedded rules bundled at compile time
static EMBEDDED_RULES: Dir = include_dir!("$CARGO_MANIFEST_DIR/config/escalation-paths/bundled");

/// Category → Severity Tier mapping
fn category_to_tier(category: &str) -> u8 {
    match category {
        "self-escalation" => 1,
        "new-passrole" | "passrole" => 2,
        "credential-access" | "new-principal" => 3,
        "data-access" => 4,
        _ => 5,
    }
}

/// Severity Tier → Boost value mapping
fn tier_to_boost(tier: u8) -> f64 {
    match tier {
        1 => 0.15,
        2 => 0.10,
        3 => 0.05,
        4 => 0.03,
        _ => 0.02,
    }
}

/// Parse a single YAML rule string
pub fn parse_rule(yaml: &str) -> Result<EscalationRule, RuleError> {
    let yaml_rule: YamlRule =
        serde_yaml::from_str(yaml).map_err(|e| RuleError::ParseError(e.to_string()))?;

    let severity_tier = category_to_tier(&yaml_rule.category);
    let boost = tier_to_boost(severity_tier);

    Ok(EscalationRule {
        id: yaml_rule.id,
        name: yaml_rule.name,
        category: yaml_rule.category,
        services: yaml_rule.services,
        permissions_required: yaml_rule.permissions.required,
        prerequisites: yaml_rule.prerequisites,
        severity_tier,
        boost,
        description: yaml_rule.description,
    })
}

/// Load rules from the bundled directory at compile time. Production code path.
/// Errors propagate — empty result means missing/corrupt embedded rules, not "no rules".
pub fn load_rules_from_embedded() -> Result<Vec<EscalationRule>, RuleError> {
    let mut rules = Vec::new();
    for file in EMBEDDED_RULES.files() {
        let path = file.path();
        if path.extension().and_then(|s| s.to_str()) != Some("yaml")
            && path.extension().and_then(|s| s.to_str()) != Some("yml")
        {
            continue;
        }
        let contents = file.contents_utf8().ok_or_else(|| {
            RuleError::LoadError(format!("rule file {} not valid utf-8", path.display()))
        })?;
        match parse_rule(contents) {
            Ok(rule) => rules.push(rule),
            Err(e) => {
                tracing::error!(path = %path.display(), error = %e, "failed to parse bundled rule");
                return Err(e);
            }
        }
    }
    Ok(rules)
}

/// Load all rules from a directory
pub fn load_rules_from_dir(dir_path: &str) -> Result<Vec<EscalationRule>, RuleError> {
    let path = Path::new(dir_path);

    if !path.is_dir() {
        return Err(RuleError::LoadError(format!(
            "Path is not a directory: {}",
            dir_path
        )));
    }

    let mut rules = Vec::new();

    // Walk directory recursively
    for entry in std::fs::read_dir(path).map_err(|e| RuleError::LoadError(e.to_string()))? {
        let entry = entry.map_err(|e| RuleError::LoadError(e.to_string()))?;
        let file_path = entry.path();

        // Only process YAML files
        if file_path.is_file()
            && (file_path.extension().is_some_and(|ext| ext == "yaml")
                || file_path.extension().is_some_and(|ext| ext == "yml"))
        {
            let content = std::fs::read_to_string(&file_path)
                .map_err(|e| RuleError::LoadError(e.to_string()))?;

            match parse_rule(&content) {
                Ok(rule) => rules.push(rule),
                Err(e) => {
                    tracing::warn!("Failed to parse rule {}: {}", file_path.display(), e);
                }
            }
        }
    }

    if rules.is_empty() {
        return Err(RuleError::LoadError(
            "No valid rules found in directory".to_string(),
        ));
    }

    rules.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_to_tier_self_escalation() {
        assert_eq!(category_to_tier("self-escalation"), 1);
    }

    #[test]
    fn test_category_to_tier_new_passrole() {
        assert_eq!(category_to_tier("new-passrole"), 2);
    }

    #[test]
    fn test_category_to_tier_passrole() {
        assert_eq!(category_to_tier("passrole"), 2);
    }

    #[test]
    fn test_category_to_tier_credential_access() {
        assert_eq!(category_to_tier("credential-access"), 3);
    }

    #[test]
    fn test_category_to_tier_data_access() {
        assert_eq!(category_to_tier("data-access"), 4);
    }

    #[test]
    fn test_category_to_tier_other() {
        assert_eq!(category_to_tier("custom"), 5);
    }

    #[test]
    fn test_tier_to_boost() {
        assert_eq!(tier_to_boost(1), 0.15);
        assert_eq!(tier_to_boost(2), 0.10);
        assert_eq!(tier_to_boost(3), 0.05);
        assert_eq!(tier_to_boost(4), 0.03);
        assert_eq!(tier_to_boost(5), 0.02);
    }
}
