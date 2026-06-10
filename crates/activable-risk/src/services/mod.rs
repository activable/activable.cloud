//! Domain services for risk computation.
//!
//! Each service encapsulates orchestration logic for one risk query family.
//! Services consume the `GraphQueryService` port; resolvers delegate to them
//! and map domain result types to GraphQL types.

pub mod account_risk_service;
pub mod federation_risk_service;
pub mod key_management_risk_service;
pub mod resource_policy_risk_service;

pub use account_risk_service::{
    assess_account_risk, categorize_rule, AccountCategorySignals, AccountRiskResult,
    CategorySignal, PrincipalRiskSummary,
};
pub use federation_risk_service::{
    assess_federation_risk, evaluate_oidc_weakness, EvaluatedOidcProvider, FederationRiskResult,
    RiskSeverity,
};
pub use key_management_risk_service::{
    assess_key_management_risk, compute_grant_severity, compute_key_risk_score,
    extract_account_from_key_arn,
    extract_account_id_from_arn as extract_account_id_from_principal_arn, normalize_key_id,
    parse_key_policy, CreateGrantRisk, KeyManagementRiskResult, KeyPolicy, KeyPolicyStatement,
    KeyRiskError, KeyRiskSeverity,
};
pub use resource_policy_risk_service::{
    assess_resource_policy_risk, compute_resource_policy_score, evaluate_trust_boundary,
    extract_account_id_from_arn as extract_resource_account_id_from_arn, parse_resource_policy,
    CrossAccountAccess, ResourcePolicy, ResourcePolicyError, ResourcePolicyRiskResult,
    ResourcePolicySeverity, ResourcePolicyStatement,
};
