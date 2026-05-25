//! Shared helpers for policy document parsing and principal evaluation.

/// Convert a Policy.document agtype value to a JSON string.
/// The document property may decode from AGE as either a JSON string (quoted scalar)
/// or a JSON object (map), depending on how it was stored. Normalize to the policy JSON
/// string either way so the parser receives valid input.
pub fn policy_value_to_json(v: &serde_json::Value) -> Option<String> {
    if let Some(s) = v.as_str() {
        // Already a string — use it directly
        Some(s.to_string())
    } else if v.is_object() || v.is_array() {
        // Object or array — serialize to JSON string
        Some(v.to_string())
    } else {
        None
    }
}

/// Extract account ID from a principal ARN.
/// Handles ARNs like: arn:aws:iam::123456789012:role/RoleName
/// Returns the 12-digit account ID if present and non-wildcard.
pub fn extract_account_id_from_arn(principal_arn: &str) -> Option<String> {
    let parts: Vec<&str> = principal_arn.split(':').collect();
    if parts.len() >= 5 {
        let account = parts[4];
        if !account.is_empty() && account != "*" && account.len() == 12 {
            return Some(account.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn policy_value_to_json_from_string() {
        let val = json!("{ \"Statement\": [] }");
        let result = policy_value_to_json(&val);
        assert_eq!(result, Some("{ \"Statement\": [] }".to_string()));
    }

    #[test]
    fn policy_value_to_json_from_object() {
        let val = json!({"Statement": []});
        let result = policy_value_to_json(&val);
        assert!(result.is_some());
        assert!(result.unwrap().contains("Statement"));
    }

    #[test]
    fn extract_account_id_from_arn_valid() {
        let arn = "arn:aws:iam::123456789012:role/TestRole";
        let result = extract_account_id_from_arn(arn);
        assert_eq!(result, Some("123456789012".to_string()));
    }

    #[test]
    fn extract_account_id_from_arn_wildcard() {
        let arn = "arn:aws:iam::*:role/TestRole";
        let result = extract_account_id_from_arn(arn);
        assert_eq!(result, None);
    }

    #[test]
    fn extract_account_id_from_arn_no_account() {
        let arn = "arn:aws:iam:::role/TestRole";
        let result = extract_account_id_from_arn(arn);
        assert_eq!(result, None);
    }

    #[test]
    fn extract_account_id_from_arn_invalid_length() {
        let arn = "arn:aws:iam::123:role/TestRole";
        let result = extract_account_id_from_arn(arn);
        assert_eq!(result, None);
    }
}
