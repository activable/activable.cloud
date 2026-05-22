# Developer Guide: Adding a New Graph Query Primitive

This guide walks you through adding a new graph query primitive to the Activable query system. By the end, you'll have a Rust function that generates safe Cypher queries, a GraphClient method for executing them, and corresponding tests.

## When to Add a New Query Primitive

Add a new query primitive when:

- **Reusability:** The query is needed by multiple API endpoints or CLI subcommands.
- **Safety:** The query involves user-controlled parameters that must be escaped/validated.
- **Complexity:** The Cypher template is non-trivial (multiple `MATCH` clauses, aggregations, etc.).

Use the `.cypher()` escape-hatch when:

- The query is a one-off, specific to a single endpoint.
- The query uses only simple parameters (already escaped/validated upstream).

Examples of good primitives:
- **walk_edges** — recursive traversal from a starting node (reused for neighborhood queries, blast radius)
- **path_finder** — shortest paths between two nodes (reused for attack surface analysis)
- **find_by_id** — deterministic node lookup by label + ID (foundation for many queries)

Non-candidates:
- Complex role-specific aggregations used once
- Queries without user-supplied parameters

## Architecture Overview

Every query primitive spans three layers:

```
CypherBuilder (Rust)
  ↓ builds safe SQL/Cypher string
GraphClient (Rust)
  ↓ executes via deadpool-postgres pool
UniFFI + GraphQL (if exposed)
  ↓ CLI subcommand / REST endpoint
```

**Data flow:**
```
User parameters (unsafe)
  → validate_label() / escape_cypher() (Rust)
  → CypherBuilder.<method>() (generates SQL/Cypher string)
  → GraphClient.<method>() (executes via pool)
  → Parse result rows (JSON/agtype)
  → Return typed struct (Path, NodeRef, Vec<NodeRef>)
```

## Step 1: Add CypherBuilder Method

Define the Cypher template and escaping logic.

**File:** `crates/activable-graph/src/query_builder.rs`

Add a new public method to the `impl CypherBuilder` block:

```rust
/// Find all nodes reachable via a specific edge type within a depth limit.
///
/// # Arguments
/// * `start` - The starting node ID (automatically escaped)
/// * `edge_type` - The type of edges to follow (label-validated)
/// * `direction` - Outgoing, Incoming, or Both
/// * `max_depth` - Maximum number of hops (u8, limits denial-of-service)
///
/// # Example
///
/// ```ignore
/// let builder = CypherBuilder::new("aws_graph");
/// let sql = builder.reachable_via_edge(
///     &NodeId::from("arn:aws:iam::123456789012:user/alice"),
///     "CanAccess",
///     Direction::Outgoing,
///     3,
/// )?;
/// // Returns SQL string executing: MATCH (s:...)-[CanAccess*1..3]->(...) RETURN ...
/// ```
pub fn reachable_via_edge(
    &self,
    start: &NodeId,
    edge_type: &str,
    direction: Direction,
    max_depth: u8,
) -> Result<String, GraphError> {
    // Validate the edge type label
    validate_label(edge_type)?;

    // Clamp max_depth to prevent DOS
    let max_depth = std::cmp::min(max_depth, 10);

    let direction_pattern = match direction {
        Direction::Outgoing => format!("-[:{edge_type}*1..{max_depth}]->(t)"),
        Direction::Incoming => format!("<-[:{edge_type}*1..{max_depth}]-(t)"),
        Direction::Both => format!("-[:{edge_type}*1..{max_depth}]-(t)"),
    };

    Ok(format!(
        "SELECT * FROM ag_catalog.cypher('{}', $$\
         MATCH (s:{{id: '{}'}}){}  \
         RETURN t.id, labels(t) LIMIT 10000\
         $$) AS (node_id agtype, node_labels agtype)",
        self.graph_name,
        escape_cypher(&start.0),
        direction_pattern,
    ))
}
```

**Key patterns:**

- **Validation:** Call `validate_label()` on all user-supplied label/identifier parameters.
- **Escaping:** Call `escape_cypher()` on all user-supplied values interpolated into Cypher.
- **Bounds:** Use `u8` parameters and clamp them (e.g., `max_depth` capped at 10) to prevent DOS queries.
- **Error handling:** Return `Result<String, GraphError>` to propagate validation errors.
- **Comments:** Document parameters, examples, and behavior in doc comments.
- **Readability:** Use raw SQL strings (`$$...$$`) for multi-line Cypher to avoid escaping quotes.

**Reference implementation:** [`crates/activable-graph/src/query_builder.rs`](../crates/activable-graph/src/query_builder.rs) lines 79–166 (see `find_by_id`, `walk_edges`, `path_finder`)

## Step 2: Add GraphClient Method

Implement execution and result parsing.

**File:** `crates/activable-graph/src/client.rs`

Add a new public async method to the `impl GraphClient` block:

```rust
/// Find all nodes reachable via a specific edge type within a depth limit.
///
/// # Arguments
/// * `start` - The starting node
/// * `edge_type` - The type of edge to follow
/// * `direction` - Direction of traversal
/// * `max_depth` - Maximum hop limit
///
/// # Returns
/// A vector of reachable nodes, or an error if the query fails.
///
/// # Example
/// ```ignore
/// let nodes = client.reachable_via_edge(
///     &NodeId::from("arn:aws:iam::..."),
///     "CanAccess",
///     Direction::Outgoing,
///     3,
/// ).await?;
/// println!("Found {} reachable nodes", nodes.len());
/// ```
pub async fn reachable_via_edge(
    &self,
    start: &NodeId,
    edge_type: &str,
    direction: Direction,
    max_depth: u8,
) -> Result<Vec<NodeRef>, GraphError> {
    let builder = CypherBuilder::new(&self.graph_name);
    let sql = builder.reachable_via_edge(start, edge_type, direction, max_depth)?;

    let client = self.pool.get().await?;
    let rows = client.query(&sql, &[]).await?;

    let mut results = Vec::with_capacity(rows.len());
    for row in rows {
        // Parse agtype node ID (returned as bytes)
        let node_id_bytes: Vec<u8> = row.try_get(0).unwrap_or_default();
        let node_id_str = String::from_utf8(node_id_bytes).unwrap_or_default();
        let id_str = node_id_str.trim_matches('"').to_string();

        // For a more complete implementation, also parse labels from row[1]
        let label = "Unknown".to_string();

        results.push(NodeRef::new(id_str, label));
    }

    Ok(results)
}
```

**Key patterns:**

- **Async:** Use `async/await` with `tokio` runtime; all database operations are async.
- **Pool checkout:** Call `self.pool.get().await?` to get a connection; errors propagate via `?`.
- **Result parsing:** `client.query()` returns a `Vec<Row>`; use `row.try_get(column_idx)` to extract fields.
- **Agtype handling:** Postgres returns agtype columns as `Vec<u8>` (binary); convert to `String` and trim quotes.
- **Capacity hints:** Use `Vec::with_capacity()` to pre-allocate; avoids reallocations during iteration.
- **Error propagation:** Use `?` operator; do not wrap errors a second time.

**Streaming vs. collected decision:**

- **Streaming** (like `walk_edges`): Return `Result<Vec<NodeRef>>` when results fit in memory (< 100k rows).
- **Collected** (like `path_finder`): Return `Vec<Path>` when each result is a structured object.
- **Streaming API future:** For very large result sets (1M+ rows), add a stream-returning variant later; not in v1.

**Reference implementation:** [`crates/activable-graph/src/client.rs`](../crates/activable-graph/src/client.rs) lines 46–100 (see `find_by_id`, `walk_edges`)

## Step 3: Unit Test — Cypher Generation

Test the query builder in isolation (no database needed).

**File:** `crates/activable-graph/src/query_builder.rs` (add tests at the bottom)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reachable_via_edge_outgoing() {
        let builder = CypherBuilder::new("aws_graph");
        let start = NodeId::from("arn:aws:iam::123456789012:user/alice");
        let result = builder.reachable_via_edge(
            &start,
            "CanAccess",
            Direction::Outgoing,
            3,
        );

        assert!(result.is_ok());
        let sql = result.unwrap();

        // Verify the generated SQL contains expected components
        assert!(sql.contains("ag_catalog.cypher"));
        assert!(sql.contains("aws_graph"));
        assert!(sql.contains("CanAccess"));
        assert!(sql.contains("*1..3"));
        assert!(sql.contains("LIMIT 10000"));
    }

    #[test]
    fn test_reachable_via_edge_invalid_label() {
        let builder = CypherBuilder::new("aws_graph");
        let start = NodeId::from("arn:aws:iam::123456789012:user/alice");
        
        // Invalid edge type (contains spaces)
        let result = builder.reachable_via_edge(
            &start,
            "Invalid Edge",  // INVALID
            Direction::Outgoing,
            3,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_reachable_via_edge_escapes_node_id() {
        let builder = CypherBuilder::new("aws_graph");
        // ARN with special characters
        let start = NodeId::from("arn:aws:iam::123456789012:user/alice\\'s");
        let result = builder.reachable_via_edge(
            &start,
            "CanAccess",
            Direction::Outgoing,
            5,
        );

        assert!(result.is_ok());
        let sql = result.unwrap();
        
        // Verify the single quote is escaped (twice: once for Cypher, once for display)
        assert!(sql.contains("alice\\\\'s") || sql.contains("alice\\\\\\'s"));
    }

    #[test]
    fn test_reachable_via_edge_direction_both() {
        let builder = CypherBuilder::new("aws_graph");
        let start = NodeId::from("arn:aws:iam::123456789012:user/alice");
        let result = builder.reachable_via_edge(
            &start,
            "CanAccess",
            Direction::Both,
            2,
        );

        assert!(result.is_ok());
        let sql = result.unwrap();
        
        // Verify both-direction syntax (no explicit arrow direction)
        assert!(sql.contains("-["));
    }
}
```

**Coverage:** Aim for ≥98% branch coverage. Test:

- Happy path (valid inputs)
- Label validation (invalid identifiers rejected)
- Escaping (special characters in node IDs)
- All direction variants (Outgoing, Incoming, Both)
- Depth clamping (max_depth > 10 is capped)

## Step 4: Integration Test

Test end-to-end against a live Postgres+AGE database.

**File:** `crates/activable-graph/tests/integration_test.rs` (add new test function)

Gate integration tests on environment variable:

```rust
#[tokio::test]
async fn test_reachable_via_edge_integration() {
    // Skip if AGE_TEST_URL not set
    let test_url = match std::env::var("AGE_TEST_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("Skipping integration test; set AGE_TEST_URL to enable");
            return;
        }
    };

    // Set up pool
    let config = deadpool_postgres::Config {
        host: Some("localhost".to_string()),
        port: Some(5433),
        // ... other config from AGE_TEST_URL
    };
    let pool = config.create_pool(
        tokio_postgres::NoTls,
    ).expect("Failed to create pool");

    let client = GraphClient::new(std::sync::Arc::new(pool), "test_graph");

    // Assume test data is already loaded (fixture setup)
    let start = NodeId::from("test_node_id");
    let results = client.reachable_via_edge(
        &start,
        "TestEdge",
        Direction::Outgoing,
        2,
    ).await;

    assert!(results.is_ok());
    let nodes = results.unwrap();
    assert!(!nodes.is_empty());
    assert!(nodes.len() <= 10000);  // LIMIT constraint
}
```

**Integration test strategy:**

- Gate on `AGE_TEST_URL` env var (CI sets this; local dev can opt-in).
- Reuse a shared test fixture (pre-loaded graph) across multiple integration tests.
- Test only behavior differences from the unit test (e.g., actual parsing, pool interaction).
- Verify the query actually executes and returns results.

**Reference:** See `crates/activable-graph/tests/` if integration tests are present.

## Step 5: FFI Exposure (if needed)

If Go code needs to call this query, expose it via UniFFI.

**File:** `crates/activable-ffi/src/query_surface.rs`

Add a wrapper function:

```rust
/// Find all nodes reachable via a specific edge type.
///
/// Exported to Go via UniFFI.
#[uniffi::export]
pub async fn reachable_via_edge_ffi(
    start: String,
    edge_type: String,
    direction: i32,  // 0 = Outgoing, 1 = Incoming, 2 = Both
    max_depth: u8,
) -> Result<Vec<String>, String> {
    let start_node = NodeId::from(start);
    let dir = match direction {
        0 => Direction::Outgoing,
        1 => Direction::Incoming,
        2 => Direction::Both,
        _ => return Err("Invalid direction".to_string()),
    };

    match CLIENT.reachable_via_edge(&start_node, &edge_type, dir, max_depth).await {
        Ok(nodes) => Ok(nodes.iter().map(|n| n.id.clone()).collect()),
        Err(e) => Err(e.to_string()),
    }
}
```

Add to `activable.udl`:

```
namespace activable {
    sequence<string> ReachableViaEdgeResult(string start, string edge_type, u32 direction, u8 max_depth);
};
```

## Step 6: Add CLI Subcommand (if needed)

If this is a public query, expose it via the CLI.

**File:** `go/cmd/activable/query_<primitive>.go`

```go
package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/activable-cloud/activable.cloud/go/internal/api"
)

var queryReachableViaEdgeCmd = &cobra.Command{
	Use:   "reachable-via-edge <node-id> <edge-type> <direction> <max-depth>",
	Short: "Find all nodes reachable via a specific edge type",
	Long: `Find all nodes reachable via a specific edge type within a depth limit.

Direction: 0 (Outgoing), 1 (Incoming), 2 (Both)

Example:
  activable query reachable-via-edge arn:aws:iam::123456789012:user/alice CanAccess 0 3
`,
	Args: cobra.ExactArgs(4),
	RunE: func(cmd *cobra.Command, args []string) error {
		nodeID := args[0]
		edgeType := args[1]
		direction := args[2]
		maxDepth := args[3]

		// Call Rust FFI or HTTP API
		result, err := api.ReachableViaEdge(cmd.Context(), nodeID, edgeType, direction, maxDepth)
		if err != nil {
			return fmt.Errorf("query failed: %w", err)
		}

		fmt.Printf("Found %d reachable nodes:\n", len(result))
		for _, node := range result {
			fmt.Printf("  - %s\n", node)
		}

		return nil
	},
}

func init() {
	queryCmd.AddCommand(queryReachableViaEdgeCmd)
}
```

Register in `go/cmd/activable/main.go`:

```go
func init() {
	queryCmd.AddCommand(queryReachableViaEdgeCmd)
}
```

## Step 7: PR Checklist

Before opening a pull request, verify:

- [ ] **CypherBuilder method added:** New method in `crates/activable-graph/src/query_builder.rs` with doc comment.
- [ ] **Validation applied:** All labels validated via `validate_label()`.
- [ ] **Escaping applied:** All user-supplied values escaped via `escape_cypher()` or `escape_sql_literal()`.
- [ ] **Bounds checked:** Numeric parameters (depth, limits) bounded to prevent DOS.
- [ ] **Error handling:** `Result<_, GraphError>` returned; errors propagated via `?`.
- [ ] **Unit tests ≥98%:** Test valid inputs, invalid labels, escaping, all direction variants.
- [ ] **Integration test added:** Gated on `AGE_TEST_URL` env var; uses test fixture.
- [ ] **GraphClient method tested:** Both unit tests (Cypher generation) and integration tests (execution).
- [ ] **FFI binding (if needed):** Function wrapped in `activable-ffi`, exported via `activable.udl`.
- [ ] **CLI subcommand (if public):** Registered in `go/cmd/activable/` with usage doc.
- [ ] **cargo clippy clean:** `cargo clippy --all-targets -- -D warnings` reports no issues.
- [ ] **cargo test clean:** `cargo test --lib` and `cargo test --test '*' --features integration` pass.
- [ ] **go vet clean:** `go vet ./go/cmd/activable/...` if CLI added.
- [ ] **No TODO/FIXME:** All query logic is complete.
- [ ] **Names follow conventions:** Use full English words (no abbreviations per CLAUDE.md §0.5).

---

**Next:** After merging, add integration tests for the GraphQL API endpoint that calls this query.
