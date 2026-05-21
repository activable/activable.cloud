//! Activable IAM evaluator — Parliament port (Slice B stub).
//!
//! SLICE-B-STUB: This crate is a placeholder for the Parliament-to-Rust port.
//! Parliament integration is deferred to Slice B; this crate exports nothing functional.
//! See plans/260521-1130-slice-a-graph-schema-aws-ingest/plan.md § "Out of scope".

/// Placeholder for IAM evaluator.
/// Populated during Slice B.
pub mod evaluator {
    /// Stub evaluator function.
    /// Will evaluate IAM policies in Slice B.
    #[allow(unconditional_panic)]
    pub fn evaluate() {
        unimplemented!("IAM evaluator porting deferred to Slice B")
    }
}
