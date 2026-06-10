//! IAM policy evaluator — Parliament-equivalent.
//!
//! Deep IAM policy parsing, Allow/Deny evaluation, permission boundary
//! intersection, and escalation edge derivation.

pub mod abac;
pub mod action_matcher;
pub mod boundary_evaluator;
pub mod cloudtrail;
pub mod condition_evaluator;
pub mod dangerous_actions;
pub mod deny_engine;
pub mod effective_permissions;
pub mod error;
pub mod escalation_derivation;
pub mod eval_context;
pub mod federation;
pub mod policy_drift;
pub mod policy_parser;
pub mod resource_matcher;
pub mod resource_policy_evaluator;
pub mod resource_policy_parser;
pub mod scp_evaluator;
pub mod session_policy;
pub mod types;

#[cfg(test)]
mod phase_04_tests;
#[cfg(test)]
mod tests;

// Re-export public API
pub use abac::{
    analyze_tag_manipulation_risk, detect_unguarded_tag_manipulation, extract_tag_dependencies,
    TagConditionType, TagDependency, TagManipulationRisk, TagRiskLevel,
};
pub use action_matcher::action_matches;
pub use boundary_evaluator::{boundary_allows, evaluate_with_boundary, BoundaryResult};
pub use cloudtrail::{
    compute_escalation_score, detect_escalation_attempts, parse_cloudtrail_batch,
    parse_cloudtrail_event, CloudTrailBatchResult, CloudTrailEvent, CloudTrailResource,
    EscalationAttempt, EscalationPattern,
};
pub use condition_evaluator::evaluate_condition;
pub use dangerous_actions::{
    detect_dangerous_actions, load_dangerous_actions_registry, DangerousAction,
    DangerousActionMatch, EffectivePermission as DangerousActionEffectivePermission, Severity,
};
pub use deny_engine::{evaluate_deny, evaluate_deny_with_context, EvalResult};
pub use effective_permissions::{effective_permissions, EffectivePermission};
pub use error::{PolicyParseError, PolicyParseResult};
pub use escalation_derivation::{derive_escalation_edges, EscalationEdge};
pub use eval_context::EvalContext;
pub use federation::{
    detect_weakness, extract_federation_trusts, find_weak_federation_trusts, FederationCondition,
    FederationProviderType, FederationTrust, FederationWeakness,
};
pub use policy_drift::{
    analyze_version_history, compute_drift_score, diff_policies, DriftSeverity, PolicyDiff,
    PolicyVersion,
};
pub use policy_parser::parse_policy;
pub use resource_matcher::resource_matches;
pub use resource_policy_evaluator::{
    evaluate_resource_policy_pair, extract_account_from_arn, principal_matches,
    ResourcePolicyDecision,
};
pub use resource_policy_parser::{parse_resource_policy, PolicyPrincipal, ResourcePolicy};
pub use scp_evaluator::scp_allows;
pub use session_policy::{
    effective_permissions_with_session, session_allows, SessionConstraintResult,
};
pub use types::{ActionPattern, Condition, Effect, ParsedPolicy, PolicyStatement, ResourcePattern};
