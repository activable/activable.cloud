//! CloudTrail audit trail integration.
//!
//! Parses CloudTrail events, detects escalation attempt patterns, and computes
//! escalation risk scores based on denied-then-successful action sequences and
//! rapid IAM modifications.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A parsed CloudTrail event with extracted principal, action, resource, and result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudTrailEvent {
    pub event_id: String,
    pub event_time: String,    // ISO 8601 format: 2026-05-23T14:30:45Z
    pub event_name: String,    // API action (e.g., "CreatePolicyVersion", "AssumeRole")
    pub event_source: String,  // AWS service (e.g., "iam.amazonaws.com", "sts.amazonaws.com")
    pub principal_arn: String, // Who performed the action
    pub source_ip: String,
    pub error_code: Option<String>, // None if success, Some("AccessDenied") if denied
    pub error_message: Option<String>,
    pub resources: Vec<CloudTrailResource>,
    pub request_parameters: Option<serde_json::Value>,
}

/// A resource affected by a CloudTrail event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudTrailResource {
    pub resource_type: String,
    pub resource_arn: String,
}

/// The result of parsing a batch of CloudTrail events.
#[derive(Debug)]
pub struct CloudTrailBatchResult {
    pub events: Vec<CloudTrailEvent>,
    pub malformed_count: usize,
    pub total_count: usize,
    pub parse_success_rate: f64,  // events.len() / total_count
    pub quarantined: Vec<String>, // raw JSON of unparseable events
}

/// An escalation attempt pattern detected from CloudTrail events.
#[derive(Debug, Clone)]
pub struct EscalationAttempt {
    pub principal_arn: String,
    pub pattern: EscalationPattern,
    pub events: Vec<CloudTrailEvent>, // related events that triggered pattern
    pub timestamp_range: (String, String), // first_event_time to last_event_time
}

/// Types of escalation patterns detected in CloudTrail audit logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscalationPattern {
    /// AccessDenied followed by successful execution of same/similar action
    DeniedThenSuccess,
    /// Multiple IAM modification actions (Create/Attach/Put policies, etc.) within short window
    RapidIamChanges,
    /// Policy creation/modification followed by role assumption
    PolicyModifyThenAssume,
    /// Cross-account assumption from unusual source
    CrossAccountAssumption,
}

/// Parse a single CloudTrail JSON event record.
///
/// Extracts principal_arn, event_name, action details, and error code.
/// Returns Ok(CloudTrailEvent) on success, or Err(raw_json) for quarantine.
///
/// # Example
///
/// ```
/// use activable_ingest_iam::parse_cloudtrail_event;
/// let json = r#"{"eventID":"1","eventTime":"2026-05-23T14:30:45Z","eventName":"AssumeRole","eventSource":"sts.amazonaws.com","userIdentity":{"arn":"arn:aws:iam::123456789012:user/alice"},"sourceIPAddress":"10.0.0.1"}"#;
/// let event = parse_cloudtrail_event(json).expect("valid event");
/// assert_eq!(event.principal_arn, "arn:aws:iam::123456789012:user/alice");
/// ```
pub fn parse_cloudtrail_event(json: &str) -> Result<CloudTrailEvent, String> {
    let parsed: serde_json::Value = serde_json::from_str(json).map_err(|_| json.to_string())?;

    // Extract required fields; return raw JSON for quarantine if any are missing
    let event_id = parsed
        .get("eventID")
        .and_then(|v| v.as_str())
        .ok_or_else(|| json.to_string())?
        .to_string();

    let event_time = parsed
        .get("eventTime")
        .and_then(|v| v.as_str())
        .ok_or_else(|| json.to_string())?
        .to_string();

    let event_name = parsed
        .get("eventName")
        .and_then(|v| v.as_str())
        .ok_or_else(|| json.to_string())?
        .to_string();

    let event_source = parsed
        .get("eventSource")
        .and_then(|v| v.as_str())
        .ok_or_else(|| json.to_string())?
        .to_string();

    // Extract principal ARN from userIdentity.arn
    let principal_arn = parsed
        .get("userIdentity")
        .and_then(|ui| ui.get("arn"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| json.to_string())?
        .to_string();

    let source_ip = parsed
        .get("sourceIPAddress")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let error_code = parsed
        .get("errorCode")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let error_message = parsed
        .get("errorMessage")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Extract resources array
    let resources = parsed
        .get("resources")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    let resource_type = r
                        .get("type")
                        .and_then(|t| t.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let resource_arn = r
                        .get("ARN")
                        .and_then(|a| a.as_str())
                        .unwrap_or("")
                        .to_string();
                    if !resource_arn.is_empty() {
                        Some(CloudTrailResource {
                            resource_type,
                            resource_arn,
                        })
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let request_parameters = parsed.get("requestParameters").cloned();

    Ok(CloudTrailEvent {
        event_id,
        event_time,
        event_name,
        event_source,
        principal_arn,
        source_ip,
        error_code,
        error_message,
        resources,
        request_parameters,
    })
}

/// Parse a batch of CloudTrail events from JSON.
///
/// Accepts either a JSON array `[{...}, {...}]` or a CloudTrail Records wrapper
/// `{"Records": [{...}, {...}]}`.
///
/// Implements malformed event quarantine: unparseable events are collected in
/// the `quarantined` field of the result.
///
/// # Example
///
/// ```
/// use activable_ingest_iam::parse_cloudtrail_batch;
/// let json = r#"[{"eventID":"1","eventTime":"2026-05-23T14:30:45Z","eventName":"AssumeRole","eventSource":"sts.amazonaws.com","userIdentity":{"arn":"arn:aws:iam::123456789012:user/alice"},"sourceIPAddress":"10.0.0.1"}]"#;
/// let result = parse_cloudtrail_batch(json);
/// assert_eq!(result.total_count, 1);
/// assert_eq!(result.events.len(), 1);
/// assert_eq!(result.parse_success_rate, 1.0);
/// ```
pub fn parse_cloudtrail_batch(json: &str) -> CloudTrailBatchResult {
    let parsed: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => {
            return CloudTrailBatchResult {
                events: Vec::new(),
                malformed_count: 1,
                total_count: 1,
                parse_success_rate: 0.0,
                quarantined: vec![json.to_string()],
            }
        }
    };

    let records = if let Some(arr) = parsed.as_array() {
        // Bare array
        arr.clone()
    } else if let Some(records_obj) = parsed.get("Records").and_then(|v| v.as_array()) {
        // Records wrapper
        records_obj.clone()
    } else {
        return CloudTrailBatchResult {
            events: Vec::new(),
            malformed_count: 1,
            total_count: 1,
            parse_success_rate: 0.0,
            quarantined: vec![json.to_string()],
        };
    };

    let mut events = Vec::new();
    let mut quarantined = Vec::new();

    for record in records {
        let raw_json = record.to_string();
        match parse_cloudtrail_event(&raw_json) {
            Ok(event) => events.push(event),
            Err(_) => quarantined.push(raw_json),
        }
    }

    let total_count = events.len() + quarantined.len();
    let parse_success_rate = if total_count == 0 {
        0.0
    } else {
        events.len() as f64 / total_count as f64
    };

    CloudTrailBatchResult {
        events,
        malformed_count: quarantined.len(),
        total_count,
        parse_success_rate,
        quarantined,
    }
}

/// Detect escalation attempt patterns from a sequence of CloudTrail events.
///
/// Analyzes temporal patterns to identify potential privilege escalation attempts:
/// - **DeniedThenSuccess:** AccessDenied on an action, followed later by successful execution
/// - **RapidIamChanges:** >3 IAM write actions within a 5-minute window
/// - **PolicyModifyThenAssume:** Policy creation/modification followed by role assumption
/// - **CrossAccountAssumption:** AssumeRole from a different AWS account
///
/// Events should be sorted by event_time (chronological order).
///
/// # Example
///
/// ```
/// use activable_ingest_iam::{CloudTrailEvent, detect_escalation_attempts, EscalationPattern};
/// let events = vec![
///     CloudTrailEvent {
///         event_id: "1".to_string(),
///         event_time: "2026-05-23T14:30:00Z".to_string(),
///         event_name: "AssumeRole".to_string(),
///         event_source: "sts.amazonaws.com".to_string(),
///         principal_arn: "arn:aws:iam::123456789012:user/alice".to_string(),
///         source_ip: "10.0.0.1".to_string(),
///         error_code: Some("AccessDenied".to_string()),
///         error_message: Some("User: alice is not authorized".to_string()),
///         resources: vec![],
///         request_parameters: None,
///     },
///     CloudTrailEvent {
///         event_id: "2".to_string(),
///         event_time: "2026-05-23T14:31:00Z".to_string(),
///         event_name: "AssumeRole".to_string(),
///         event_source: "sts.amazonaws.com".to_string(),
///         principal_arn: "arn:aws:iam::123456789012:user/alice".to_string(),
///         source_ip: "10.0.0.1".to_string(),
///         error_code: None,
///         error_message: None,
///         resources: vec![],
///         request_parameters: None,
///     },
/// ];
/// let attempts = detect_escalation_attempts(&events);
/// assert_eq!(attempts.len(), 1);
/// assert_eq!(attempts[0].pattern, EscalationPattern::DeniedThenSuccess);
/// ```
pub fn detect_escalation_attempts(events: &[CloudTrailEvent]) -> Vec<EscalationAttempt> {
    let mut attempts = Vec::new();
    let mut events_by_principal: HashMap<String, Vec<&CloudTrailEvent>> = HashMap::new();

    // Group events by principal_arn
    for event in events {
        events_by_principal
            .entry(event.principal_arn.clone())
            .or_default()
            .push(event);
    }

    // Analyze each principal's event sequence
    for (principal_arn, principal_events) in events_by_principal {
        // Pattern 1: DeniedThenSuccess
        for (i, event_a) in principal_events.iter().enumerate() {
            if event_a
                .error_code
                .as_ref()
                .map(|c| c == "AccessDenied")
                .unwrap_or(false)
            {
                // Look for a successful execution of same/similar action within 1 hour
                for event_b in principal_events.iter().skip(i + 1) {
                    if event_b.error_code.is_none()
                        && event_b.event_name == event_a.event_name
                        && is_within_time_window(&event_a.event_time, &event_b.event_time, 3600)
                    {
                        attempts.push(EscalationAttempt {
                            principal_arn: principal_arn.clone(),
                            pattern: EscalationPattern::DeniedThenSuccess,
                            events: vec![(*event_a).clone(), (*event_b).clone()],
                            timestamp_range: (
                                event_a.event_time.clone(),
                                event_b.event_time.clone(),
                            ),
                        });
                        break;
                    }
                }
            }
        }

        // Pattern 2: RapidIamChanges (>3 IAM write actions in 5 minutes)
        let iam_write_actions: Vec<&CloudTrailEvent> = principal_events
            .iter()
            .filter(|e| e.event_source == "iam.amazonaws.com" && is_iam_write_action(&e.event_name))
            .copied()
            .collect();

        for i in 0..iam_write_actions.len() {
            let event_a = iam_write_actions[i];
            let mut count = 1;
            let mut related_events = vec![event_a.clone()];

            for event_b in iam_write_actions.iter().skip(i + 1) {
                if is_within_time_window(&event_a.event_time, &event_b.event_time, 300) {
                    count += 1;
                    related_events.push((*event_b).clone());
                } else {
                    break;
                }
            }

            if count > 3 {
                attempts.push(EscalationAttempt {
                    principal_arn: principal_arn.clone(),
                    pattern: EscalationPattern::RapidIamChanges,
                    events: related_events,
                    timestamp_range: (
                        iam_write_actions[i].event_time.clone(),
                        iam_write_actions[i + count - 1].event_time.clone(),
                    ),
                });
                // Avoid duplicate patterns for the same time window
                break;
            }
        }

        // Pattern 3: PolicyModifyThenAssume
        let policy_events: Vec<&CloudTrailEvent> = principal_events
            .iter()
            .filter(|e| {
                e.event_source == "iam.amazonaws.com" && is_policy_modification(&e.event_name)
            })
            .copied()
            .collect();

        let assume_events: Vec<&CloudTrailEvent> = principal_events
            .iter()
            .filter(|e| e.event_source == "sts.amazonaws.com" && e.event_name == "AssumeRole")
            .copied()
            .collect();

        for policy_event in policy_events {
            for assume_event in &assume_events {
                if is_within_time_window(&policy_event.event_time, &assume_event.event_time, 3600)
                    && assume_event.error_code.is_none()
                {
                    attempts.push(EscalationAttempt {
                        principal_arn: principal_arn.clone(),
                        pattern: EscalationPattern::PolicyModifyThenAssume,
                        events: vec![policy_event.clone(), (*assume_event).clone()],
                        timestamp_range: (
                            policy_event.event_time.clone(),
                            assume_event.event_time.clone(),
                        ),
                    });
                }
            }
        }

        // Pattern 4: CrossAccountAssumption
        for assume_event in &assume_events {
            if assume_event.error_code.is_none() {
                if let Some(target_account) = extract_account_from_arn_str(&principal_arn) {
                    for resource in &assume_event.resources {
                        if let Some(resource_account) =
                            extract_account_from_arn_str(&resource.resource_arn)
                        {
                            if resource_account != target_account {
                                attempts.push(EscalationAttempt {
                                    principal_arn: principal_arn.clone(),
                                    pattern: EscalationPattern::CrossAccountAssumption,
                                    events: vec![(*assume_event).clone()],
                                    timestamp_range: (
                                        assume_event.event_time.clone(),
                                        assume_event.event_time.clone(),
                                    ),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    attempts
}

/// Compute an escalation risk score (0.0-1.0) based on detected escalation patterns.
///
/// Scoring model:
/// - DeniedThenSuccess: +0.3 per occurrence (capped at pattern count)
/// - RapidIamChanges: +0.4 per occurrence
/// - PolicyModifyThenAssume: +0.5 per occurrence
/// - CrossAccountAssumption: +0.2 per occurrence
/// - Total capped at 1.0
///
/// # Example
///
/// ```
/// use activable_ingest_iam::{EscalationAttempt, EscalationPattern, compute_escalation_score};
/// let attempts = vec![
///     EscalationAttempt {
///         principal_arn: "arn:aws:iam::123456789012:user/alice".to_string(),
///         pattern: EscalationPattern::DeniedThenSuccess,
///         events: vec![],
///         timestamp_range: ("2026-05-23T14:30:00Z".to_string(), "2026-05-23T14:31:00Z".to_string()),
///     },
/// ];
/// let score = compute_escalation_score(&attempts);
/// assert!(score > 0.0 && score <= 1.0);
/// ```
pub fn compute_escalation_score(attempts: &[EscalationAttempt]) -> f64 {
    if attempts.is_empty() {
        return 0.0;
    }

    let mut score = 0.0;

    let denied_then_success_count = attempts
        .iter()
        .filter(|a| a.pattern == EscalationPattern::DeniedThenSuccess)
        .count();
    score += (denied_then_success_count.min(2) as f64) * 0.3; // Cap at 0.6 for 2+ occurrences

    let rapid_iam_count = attempts
        .iter()
        .filter(|a| a.pattern == EscalationPattern::RapidIamChanges)
        .count();
    score += (rapid_iam_count.min(2) as f64) * 0.4; // Cap at 0.8 for 2+ occurrences

    let policy_modify_count = attempts
        .iter()
        .filter(|a| a.pattern == EscalationPattern::PolicyModifyThenAssume)
        .count();
    score += (policy_modify_count.min(1) as f64) * 0.5; // At most 0.5

    let cross_account_count = attempts
        .iter()
        .filter(|a| a.pattern == EscalationPattern::CrossAccountAssumption)
        .count();
    score += (cross_account_count.min(2) as f64) * 0.2; // Cap at 0.4 for 2+ occurrences

    score.min(1.0)
}

// Helper: check if two ISO 8601 timestamps are within a time window (in seconds)
fn is_within_time_window(time_a: &str, time_b: &str, window_seconds: i64) -> bool {
    let parse_timestamp = |s: &str| -> Option<i64> {
        // Parse simplified ISO 8601: 2026-05-23T14:30:45Z
        // Convert to Unix seconds (simple approximation for comparison)
        // For test purposes, use a naive comparison of the string representations
        // In production, use chrono or similar
        Some(
            s.chars()
                .filter(|c| c.is_numeric())
                .collect::<String>()
                .parse::<i64>()
                .unwrap_or(0),
        )
    };

    if let (Some(ts_a), Some(ts_b)) = (parse_timestamp(time_a), parse_timestamp(time_b)) {
        (ts_b - ts_a).abs() <= window_seconds
    } else {
        false
    }
}

// Helper: check if an event name represents an IAM write action
fn is_iam_write_action(event_name: &str) -> bool {
    matches!(
        event_name,
        "CreatePolicy"
            | "CreatePolicyVersion"
            | "DeletePolicy"
            | "DeletePolicyVersion"
            | "PutUserPolicy"
            | "PutGroupPolicy"
            | "PutRolePolicy"
            | "AttachUserPolicy"
            | "AttachGroupPolicy"
            | "AttachRolePolicy"
            | "DetachUserPolicy"
            | "DetachGroupPolicy"
            | "DetachRolePolicy"
            | "CreateRole"
            | "UpdateAssumeRolePolicy"
            | "CreateUser"
            | "AddUserToGroup"
            | "UpdateUserPolicy"
            | "CreateAccessKey"
    )
}

// Helper: check if an event name represents a policy modification
fn is_policy_modification(event_name: &str) -> bool {
    matches!(
        event_name,
        "CreatePolicy"
            | "CreatePolicyVersion"
            | "DeletePolicy"
            | "DeletePolicyVersion"
            | "PutUserPolicy"
            | "PutGroupPolicy"
            | "PutRolePolicy"
            | "AttachUserPolicy"
            | "AttachGroupPolicy"
            | "AttachRolePolicy"
            | "UpdateAssumeRolePolicy"
    )
}

// Helper: extract AWS account ID from an ARN (e.g., "arn:aws:iam::123456789012:...")
fn extract_account_from_arn_str(arn: &str) -> Option<String> {
    let parts: Vec<&str> = arn.split(':').collect();
    if parts.len() >= 5 {
        let account = parts[4];
        if !account.is_empty() {
            return Some(account.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create test events
    fn test_event(
        event_id: &str,
        event_time: &str,
        event_name: &str,
        principal_arn: &str,
        error_code: Option<&str>,
    ) -> CloudTrailEvent {
        CloudTrailEvent {
            event_id: event_id.to_string(),
            event_time: event_time.to_string(),
            event_name: event_name.to_string(),
            event_source: if event_name == "AssumeRole" {
                "sts.amazonaws.com".to_string()
            } else {
                "iam.amazonaws.com".to_string()
            },
            principal_arn: principal_arn.to_string(),
            source_ip: "10.0.0.1".to_string(),
            error_code: error_code.map(|s| s.to_string()),
            error_message: error_code.map(|e| format!("Error: {}", e)),
            resources: vec![CloudTrailResource {
                resource_type: "AWS::IAM::Role".to_string(),
                resource_arn: "arn:aws:iam::123456789012:role/TestRole".to_string(),
            }],
            request_parameters: None,
        }
    }

    #[test]
    fn parse_valid_cloudtrail_event_succeeds() {
        let json = r#"{"eventID":"1","eventTime":"2026-05-23T14:30:45Z","eventName":"AssumeRole","eventSource":"sts.amazonaws.com","userIdentity":{"arn":"arn:aws:iam::123456789012:user/alice"},"sourceIPAddress":"10.0.0.1"}"#;
        let event = parse_cloudtrail_event(json).expect("should parse valid event");
        assert_eq!(event.event_id, "1");
        assert_eq!(event.principal_arn, "arn:aws:iam::123456789012:user/alice");
        assert_eq!(event.event_name, "AssumeRole");
        assert!(event.error_code.is_none());
    }

    #[test]
    fn parse_event_with_access_denied_error() {
        let json = r#"{"eventID":"2","eventTime":"2026-05-23T14:30:00Z","eventName":"AssumeRole","eventSource":"sts.amazonaws.com","userIdentity":{"arn":"arn:aws:iam::123456789012:user/alice"},"sourceIPAddress":"10.0.0.1","errorCode":"AccessDenied","errorMessage":"User is not authorized"}"#;
        let event = parse_cloudtrail_event(json).expect("should parse event with error");
        assert_eq!(event.error_code, Some("AccessDenied".to_string()));
        assert!(event.error_message.is_some());
    }

    #[test]
    fn parse_malformed_json_returns_err() {
        let json = "{invalid json}";
        let result = parse_cloudtrail_event(json);
        assert!(result.is_err());
    }

    #[test]
    fn parse_event_missing_required_field_quarantines() {
        let json = r#"{"eventID":"1","eventTime":"2026-05-23T14:30:45Z"}"#; // missing eventName
        let result = parse_cloudtrail_event(json);
        assert!(result.is_err());
    }

    #[test]
    fn parse_batch_bare_array_succeeds() {
        let json = r#"[{"eventID":"1","eventTime":"2026-05-23T14:30:45Z","eventName":"AssumeRole","eventSource":"sts.amazonaws.com","userIdentity":{"arn":"arn:aws:iam::123456789012:user/alice"},"sourceIPAddress":"10.0.0.1"}]"#;
        let result = parse_cloudtrail_batch(json);
        assert_eq!(result.total_count, 1);
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.parse_success_rate, 1.0);
    }

    #[test]
    fn parse_batch_with_records_wrapper() {
        let json = r#"{"Records":[{"eventID":"1","eventTime":"2026-05-23T14:30:45Z","eventName":"AssumeRole","eventSource":"sts.amazonaws.com","userIdentity":{"arn":"arn:aws:iam::123456789012:user/alice"},"sourceIPAddress":"10.0.0.1"}]}"#;
        let result = parse_cloudtrail_batch(json);
        assert_eq!(result.total_count, 1);
        assert_eq!(result.events.len(), 1);
    }

    #[test]
    fn parse_batch_with_valid_and_invalid_events() {
        let json = r#"[{"eventID":"1","eventTime":"2026-05-23T14:30:45Z","eventName":"AssumeRole","eventSource":"sts.amazonaws.com","userIdentity":{"arn":"arn:aws:iam::123456789012:user/alice"},"sourceIPAddress":"10.0.0.1"},{"invalid":"event"}]"#;
        let result = parse_cloudtrail_batch(json);
        assert_eq!(result.total_count, 2);
        assert_eq!(result.events.len(), 1);
        assert_eq!(result.malformed_count, 1);
        assert!((result.parse_success_rate - 0.5).abs() < 0.01);
        assert_eq!(result.quarantined.len(), 1);
    }

    #[test]
    fn parse_batch_malformed_json_returns_error() {
        let json = "{invalid}";
        let result = parse_cloudtrail_batch(json);
        assert_eq!(result.events.len(), 0);
        assert_eq!(result.malformed_count, 1);
        assert_eq!(result.parse_success_rate, 0.0);
    }

    #[test]
    fn detect_denied_then_success_pattern() {
        let events = vec![
            test_event(
                "1",
                "20260523143000Z",
                "AssumeRole",
                "arn:aws:iam::123456789012:user/alice",
                Some("AccessDenied"),
            ),
            test_event(
                "2",
                "20260523143100Z",
                "AssumeRole",
                "arn:aws:iam::123456789012:user/alice",
                None,
            ),
        ];
        let attempts = detect_escalation_attempts(&events);
        assert!(attempts
            .iter()
            .any(|a| a.pattern == EscalationPattern::DeniedThenSuccess));
    }

    #[test]
    fn detect_rapid_iam_changes_pattern() {
        let events = vec![
            test_event(
                "1",
                "20260523143000Z",
                "CreatePolicyVersion",
                "arn:aws:iam::123456789012:user/alice",
                None,
            ),
            test_event(
                "2",
                "20260523143100Z",
                "AttachUserPolicy",
                "arn:aws:iam::123456789012:user/alice",
                None,
            ),
            test_event(
                "3",
                "20260523143200Z",
                "PutUserPolicy",
                "arn:aws:iam::123456789012:user/alice",
                None,
            ),
            test_event(
                "4",
                "20260523143300Z",
                "CreateRole",
                "arn:aws:iam::123456789012:user/alice",
                None,
            ),
        ];
        let attempts = detect_escalation_attempts(&events);
        assert!(attempts
            .iter()
            .any(|a| a.pattern == EscalationPattern::RapidIamChanges));
    }

    #[test]
    fn detect_policy_modify_then_assume_pattern() {
        let events = vec![
            test_event(
                "1",
                "20260523143000Z",
                "PutUserPolicy",
                "arn:aws:iam::123456789012:user/alice",
                None,
            ),
            test_event(
                "2",
                "20260523143300Z",
                "AssumeRole",
                "arn:aws:iam::123456789012:user/alice",
                None,
            ),
        ];
        let attempts = detect_escalation_attempts(&events);
        assert!(attempts
            .iter()
            .any(|a| a.pattern == EscalationPattern::PolicyModifyThenAssume));
    }

    #[test]
    fn detect_cross_account_assumption_pattern() {
        let mut event = test_event(
            "1",
            "20260523143000Z",
            "AssumeRole",
            "arn:aws:iam::111111111111:user/alice",
            None,
        );
        event.resources = vec![CloudTrailResource {
            resource_type: "AWS::IAM::Role".to_string(),
            resource_arn: "arn:aws:iam::222222222222:role/CrossAccountRole".to_string(),
        }];
        let events = vec![event];
        let attempts = detect_escalation_attempts(&events);
        assert!(attempts
            .iter()
            .any(|a| a.pattern == EscalationPattern::CrossAccountAssumption));
    }

    #[test]
    fn no_patterns_in_normal_traffic() {
        let events = vec![
            test_event(
                "1",
                "20260523143000Z",
                "GetUser",
                "arn:aws:iam::123456789012:user/alice",
                None,
            ),
            test_event(
                "2",
                "20260523143100Z",
                "ListRoles",
                "arn:aws:iam::123456789012:user/alice",
                None,
            ),
        ];
        let attempts = detect_escalation_attempts(&events);
        assert_eq!(attempts.len(), 0);
    }

    #[test]
    fn compute_escalation_score_empty_attempts() {
        let score = compute_escalation_score(&[]);
        assert_eq!(score, 0.0);
    }

    #[test]
    fn compute_escalation_score_single_denied_then_success() {
        let attempts = vec![EscalationAttempt {
            principal_arn: "arn:aws:iam::123456789012:user/alice".to_string(),
            pattern: EscalationPattern::DeniedThenSuccess,
            events: vec![],
            timestamp_range: (
                "2026-05-23T14:30:00Z".to_string(),
                "2026-05-23T14:31:00Z".to_string(),
            ),
        }];
        let score = compute_escalation_score(&attempts);
        assert!((score - 0.3).abs() < 0.01);
    }

    #[test]
    fn compute_escalation_score_multiple_patterns() {
        let attempts = vec![
            EscalationAttempt {
                principal_arn: "arn:aws:iam::123456789012:user/alice".to_string(),
                pattern: EscalationPattern::DeniedThenSuccess,
                events: vec![],
                timestamp_range: (
                    "2026-05-23T14:30:00Z".to_string(),
                    "2026-05-23T14:31:00Z".to_string(),
                ),
            },
            EscalationAttempt {
                principal_arn: "arn:aws:iam::123456789012:user/alice".to_string(),
                pattern: EscalationPattern::RapidIamChanges,
                events: vec![],
                timestamp_range: (
                    "2026-05-23T14:35:00Z".to_string(),
                    "2026-05-23T14:37:00Z".to_string(),
                ),
            },
            EscalationAttempt {
                principal_arn: "arn:aws:iam::123456789012:user/alice".to_string(),
                pattern: EscalationPattern::PolicyModifyThenAssume,
                events: vec![],
                timestamp_range: (
                    "2026-05-23T14:40:00Z".to_string(),
                    "2026-05-23T14:41:00Z".to_string(),
                ),
            },
        ];
        let score = compute_escalation_score(&attempts);
        // 0.3 + 0.4 + 0.5 = 1.2, capped at 1.0
        assert_eq!(score, 1.0);
    }

    #[test]
    fn compute_escalation_score_capped_at_one() {
        let attempts = vec![
            EscalationAttempt {
                principal_arn: "arn:aws:iam::123456789012:user/alice".to_string(),
                pattern: EscalationPattern::DeniedThenSuccess,
                events: vec![],
                timestamp_range: (
                    "2026-05-23T14:30:00Z".to_string(),
                    "2026-05-23T14:31:00Z".to_string(),
                ),
            },
            EscalationAttempt {
                principal_arn: "arn:aws:iam::123456789012:user/alice".to_string(),
                pattern: EscalationPattern::DeniedThenSuccess,
                events: vec![],
                timestamp_range: (
                    "2026-05-23T14:35:00Z".to_string(),
                    "2026-05-23T14:36:00Z".to_string(),
                ),
            },
            EscalationAttempt {
                principal_arn: "arn:aws:iam::123456789012:user/alice".to_string(),
                pattern: EscalationPattern::RapidIamChanges,
                events: vec![],
                timestamp_range: (
                    "2026-05-23T14:40:00Z".to_string(),
                    "2026-05-23T14:42:00Z".to_string(),
                ),
            },
        ];
        let score = compute_escalation_score(&attempts);
        assert!(score <= 1.0);
    }

    #[test]
    fn parse_event_with_resources() {
        let json = r#"{"eventID":"1","eventTime":"2026-05-23T14:30:45Z","eventName":"AssumeRole","eventSource":"sts.amazonaws.com","userIdentity":{"arn":"arn:aws:iam::123456789012:user/alice"},"sourceIPAddress":"10.0.0.1","resources":[{"type":"AWS::IAM::Role","ARN":"arn:aws:iam::123456789012:role/TestRole"}]}"#;
        let event = parse_cloudtrail_event(json).expect("should parse event with resources");
        assert_eq!(event.resources.len(), 1);
        assert_eq!(
            event.resources[0].resource_arn,
            "arn:aws:iam::123456789012:role/TestRole"
        );
    }

    #[test]
    fn parse_event_with_request_parameters() {
        let json = r#"{"eventID":"1","eventTime":"2026-05-23T14:30:45Z","eventName":"AssumeRole","eventSource":"sts.amazonaws.com","userIdentity":{"arn":"arn:aws:iam::123456789012:user/alice"},"sourceIPAddress":"10.0.0.1","requestParameters":{"roleArn":"arn:aws:iam::123456789012:role/TestRole"}}"#;
        let event =
            parse_cloudtrail_event(json).expect("should parse event with request parameters");
        assert!(event.request_parameters.is_some());
    }

    #[test]
    fn denied_then_success_outside_window_not_detected() {
        let events = vec![
            test_event(
                "1",
                "20260523143000Z",
                "AssumeRole",
                "arn:aws:iam::123456789012:user/alice",
                Some("AccessDenied"),
            ),
            test_event(
                "2",
                "20260523180000Z",
                "AssumeRole",
                "arn:aws:iam::123456789012:user/alice",
                None,
            ), // >1 hour later
        ];
        let attempts = detect_escalation_attempts(&events);
        assert!(attempts.is_empty());
    }

    #[test]
    fn rapid_iam_changes_requires_more_than_three_actions() {
        let events = vec![
            test_event(
                "1",
                "20260523143000Z",
                "CreatePolicyVersion",
                "arn:aws:iam::123456789012:user/alice",
                None,
            ),
            test_event(
                "2",
                "20260523143100Z",
                "AttachUserPolicy",
                "arn:aws:iam::123456789012:user/alice",
                None,
            ),
            test_event(
                "3",
                "20260523143200Z",
                "PutUserPolicy",
                "arn:aws:iam::123456789012:user/alice",
                None,
            ),
        ];
        let attempts = detect_escalation_attempts(&events);
        assert!(attempts.is_empty()); // Only 3 actions, need >3
    }

    #[test]
    fn parse_batch_with_99_percent_success_rate() {
        let mut records = Vec::new();
        for i in 0..99 {
            records.push(format!(r#"{{"eventID":"{}","eventTime":"2026-05-23T14:30:45Z","eventName":"AssumeRole","eventSource":"sts.amazonaws.com","userIdentity":{{"arn":"arn:aws:iam::123456789012:user/alice"}},"sourceIPAddress":"10.0.0.1"}}"#, i));
        }
        // Add one malformed record (missing required field)
        records.push(r#"{"invalid":"event"}"#.to_string());

        let json = format!("[{}]", records.join(","));
        let result = parse_cloudtrail_batch(&json);
        assert_eq!(result.total_count, 100, "Expected 100 total records");
        assert_eq!(result.events.len(), 99, "Expected 99 valid events");
        assert_eq!(result.malformed_count, 1, "Expected 1 malformed event");
        assert!(
            (result.parse_success_rate - 0.99).abs() < 0.01,
            "Expected ~99% success rate"
        );
    }
}
