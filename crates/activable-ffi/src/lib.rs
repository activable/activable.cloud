//! UniFFI surface for activable — FFI boundary between Rust and Go.

mod error;
mod query_surface;
mod runtime;
mod write_surface;

use activable_schema as schema;

pub use error::ActivableError;
pub use query_surface::{query_blast_radius, query_find_node, query_path_finder, query_subgraph, query_walk_edges};
pub use write_surface::{add_edge, add_edges_batch, add_node, add_nodes_batch, flush, graph_initialize, health_check};

/// Returns version string from the schema crate.
#[uniffi::export]
pub fn version() -> String {
    format!("activable v{}", schema::version())
}

uniffi::setup_scaffolding!();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_ffi() {
        let v = version();
        assert!(v.contains("activable"));
        assert!(v.contains("0.1.0"));
    }
}
