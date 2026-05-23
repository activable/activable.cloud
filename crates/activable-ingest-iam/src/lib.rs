//! IAM policy evaluator — Parliament-equivalent.
//!
//! Deep IAM policy parsing, Allow/Deny evaluation, permission boundary
//! intersection, and escalation edge derivation.

pub mod action_matcher;
pub mod boundary_evaluator;
pub mod condition_evaluator;
pub mod deny_engine;
pub mod error;
pub mod eval_context;
pub mod policy_parser;
pub mod resource_matcher;
pub mod scp_evaluator;
pub mod types;

#[cfg(test)]
mod tests;

// Re-export public API
pub use action_matcher::action_matches;
pub use boundary_evaluator::{boundary_allows, evaluate_with_boundary, BoundaryResult};
pub use condition_evaluator::evaluate_condition;
pub use deny_engine::{evaluate_deny, evaluate_deny_with_context, EvalResult};
pub use error::{PolicyParseError, PolicyParseResult};
pub use eval_context::EvalContext;
pub use policy_parser::parse_policy;
pub use resource_matcher::resource_matches;
pub use scp_evaluator::scp_allows;
pub use types::{ActionPattern, Condition, Effect, ParsedPolicy, PolicyStatement, ResourcePattern};
