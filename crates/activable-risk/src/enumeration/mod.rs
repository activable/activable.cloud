pub mod iterative_scorer;
/// Multi-credential enumeration loop with iterative risk re-scoring.
///
/// This module implements automated principal discovery and iterative risk re-scoring
/// to identify cross-principal escalation chains and convergence detection.
///
/// ## Overview
///
/// The enumeration loop:
/// 1. Discovers all principals from the graph
/// 2. Scores each principal independently
/// 3. Detects escalation edges (assume-role, PassRole chains)
/// 4. Repeats until convergence (no new edges) or max iterations
/// 5. Reports statistics on principals discovered and chains found
pub mod principal_enumerator;

pub use iterative_scorer::{run_iterative_scoring, IterationConfig, IterationStats};
pub use principal_enumerator::{enumerate_principals, EnumeratedPrincipal};
