//! Principal node builder — shared across KMS, Secrets Manager, Lambda enrichers.
//! Extracts principal type, account_id, and external/service flags from ARN.

use serde_json::{json, Value};

/// Build a Principal node from an IAM principal ARN with external/service classification.
///
/// **Why external/service flags exist:** External and service access paths must be VISIBLE in the
/// attack graph (they represent potential attack surface — cross-account access and AWS service
/// integrations). Condition evaluation (whether a grant is actually reachable given conditions
/// like org ID restrictions) is deferred to a future IAM policy evaluator. An unconditioned
/// `AllowsAccessFrom` edge is a known v1 over-approximation: we record the edge and its
/// conditions, but do not currently evaluate them.
///
/// # Arguments
/// * `principal_arn` - An IAM principal ARN (role, user, account, or service principal)
/// * `caller_account_id` - The AWS account ID that owns the resource being accessed
///
/// # Returns
/// A JSON node with fields:
/// - `id`: The ARN as the canonical ID
/// - `name`: Display name (extracted from ARN)
/// - `principal_type`: One of Service, AccountRoot, Role, User, Principal
/// - `account_id`: Account ID parsed from ARN (or "000000000000" if unparseable)
/// - `service`: `true` if this is an AWS service principal (contains `.amazonaws.com`)
/// - `external`: `true` if the principal's account differs from caller_account_id (and is not a service)
pub fn build_principal_node(principal_arn: &str, caller_account_id: &str) -> Value {
    // Determine principal type: check more specific types first
    let principal_type = if principal_arn.contains(".amazonaws.com") {
        "Service"
    } else if principal_arn.contains(":root") {
        "AccountRoot"
    } else if principal_arn.contains(":role/") {
        "Role"
    } else if principal_arn.contains(":user/") {
        "User"
    } else {
        "Principal"
    };

    // Extract account ID from ARN (part 4 of colon-separated fields)
    let account_id = principal_arn
        .split(':')
        .nth(4)
        .unwrap_or("000000000000")
        .to_string();

    // Classify as service or external
    let is_service = principal_arn.contains(".amazonaws.com");
    let is_external = !is_service && account_id != caller_account_id;

    // Use last segment of ARN as display name for readability
    // Try slash-separated first (roles, users), then colon-separated (root)
    let name = if principal_arn.contains('/') {
        principal_arn
            .rsplit('/')
            .next()
            .unwrap_or(principal_arn)
            .to_string()
    } else {
        // For arns like ...::123456789012:root, extract "root"
        principal_arn
            .rsplit(':')
            .next()
            .unwrap_or(principal_arn)
            .to_string()
    };

    json!({
        "id": principal_arn,
        "name": name,
        "principal_type": principal_type,
        "account_id": account_id,
        "service": is_service,
        "external": is_external,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_same_account_role() {
        let node = build_principal_node("arn:aws:iam::999999999999:role/MyRole", "999999999999");
        assert_eq!(node["id"], "arn:aws:iam::999999999999:role/MyRole");
        assert_eq!(node["name"], "MyRole");
        assert_eq!(node["principal_type"], "Role");
        assert_eq!(node["account_id"], "999999999999");
        assert_eq!(node["service"], false);
        assert_eq!(node["external"], false);
    }

    #[test]
    fn test_cross_account_role() {
        let node =
            build_principal_node("arn:aws:iam::111111111111:role/RemoteRole", "999999999999");
        assert_eq!(node["id"], "arn:aws:iam::111111111111:role/RemoteRole");
        assert_eq!(node["name"], "RemoteRole");
        assert_eq!(node["principal_type"], "Role");
        assert_eq!(node["account_id"], "111111111111");
        assert_eq!(node["service"], false);
        assert_eq!(node["external"], true);
    }

    #[test]
    fn test_service_principal() {
        let node = build_principal_node("lambda.amazonaws.com", "999999999999");
        assert_eq!(node["id"], "lambda.amazonaws.com");
        // For service principals without colons or slashes, the whole ARN becomes the name
        assert_eq!(node["name"], "lambda.amazonaws.com");
        assert_eq!(node["principal_type"], "Service");
        assert_eq!(node["service"], true);
        assert_eq!(node["external"], false);
    }

    #[test]
    fn test_account_root() {
        let node = build_principal_node("arn:aws:iam::888888888888:root", "999999999999");
        assert_eq!(node["id"], "arn:aws:iam::888888888888:root");
        assert_eq!(node["name"], "root");
        assert_eq!(node["principal_type"], "AccountRoot");
        assert_eq!(node["account_id"], "888888888888");
        assert_eq!(node["service"], false);
        assert_eq!(node["external"], true);
    }

    #[test]
    fn test_iam_user() {
        let node = build_principal_node("arn:aws:iam::999999999999:user/alice", "999999999999");
        assert_eq!(node["id"], "arn:aws:iam::999999999999:user/alice");
        assert_eq!(node["name"], "alice");
        assert_eq!(node["principal_type"], "User");
        assert_eq!(node["account_id"], "999999999999");
        assert_eq!(node["service"], false);
        assert_eq!(node["external"], false);
    }

    #[test]
    fn test_cross_account_user() {
        let node = build_principal_node("arn:aws:iam::222222222222:user/bob", "999999999999");
        assert_eq!(node["account_id"], "222222222222");
        assert_eq!(node["external"], true);
        assert_eq!(node["service"], false);
    }

    #[test]
    fn test_malformed_arn_fallback() {
        // Test the "Principal" fallback arm (not .amazonaws.com, :root, :role/, or :user/)
        // and the default account_id "000000000000" (ARN with < 5 colon-separated fields)
        let node = build_principal_node("malformed-arn", "999999999999");
        assert_eq!(node["id"], "malformed-arn");
        assert_eq!(node["name"], "malformed-arn");
        assert_eq!(node["principal_type"], "Principal");
        assert_eq!(node["account_id"], "000000000000");
        assert_eq!(node["service"], false);
        assert_eq!(node["external"], true); // 000000000000 != 999999999999
    }

    #[test]
    fn test_arn_without_account_id() {
        // Another case: ARN-like but without enough colon-separated segments
        // This tests the unwrap_or("000000000000") branch
        let node = build_principal_node("arn:aws:iam:role/MyRole", "999999999999");
        assert_eq!(node["account_id"], "000000000000");
        assert_eq!(node["principal_type"], "Role"); // Still matches :role/
        assert_eq!(node["external"], true);
    }
}
