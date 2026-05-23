//! IAM policy evaluator — Parliament-equivalent.
//!
//! Deep IAM policy parsing, Allow/Deny evaluation, permission boundary
//! intersection, and escalation edge derivation.

pub mod action_matcher;
pub mod error;
pub mod policy_parser;
pub mod resource_matcher;
pub mod types;

// Re-export public API
pub use action_matcher::action_matches;
pub use error::{PolicyParseError, PolicyParseResult};
pub use policy_parser::parse_policy;
pub use resource_matcher::resource_matches;
pub use types::{ActionPattern, Condition, Effect, ParsedPolicy, PolicyStatement, ResourcePattern};
