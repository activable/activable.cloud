# Developer Guide: Adding a New Query Primitive

This guide walks you through adding a new query primitive to the `activable-graph` crate. A query primitive is a reusable graph traversal operation (e.g., "find all permissions reachable from a principal") that is exposed through the Rust API, UniFFI FFI boundary, and CLI.

## When to Add a New Query Primitive

Before implementing, decide between:

1. **Add a query primitive** if:
   - The operation is reusable across multiple CLI subcommands or API endpoints.
   - The operation has a clear semantic meaning ("find paths", "walk edges", "count reachable nodes").
   - You'll expose it via CLI, REST API, or GraphQL.
   - **Examples:** `path_finder` (find all paths between two nodes), `walk_edges` (enumerate neighbors at depth N), `subgraph_extraction` (collect a connected subgraph).

2. **Use `.cypher()` escape hatch** if:
   - The operation is one-off or highly specialized (e.g., "list all principals without access keys").
   - Performance is not critical (raw Cypher is acceptable latency-wise).
   - The operation won't be exposed as a public API surface.

For v1, prefer building 4–5 core primitives (walk, path, subgraph, count, filter) and deferring specialized queries to v2.

## Architecture Overview

Query primitives flow through five layers:

```
CLI (go/cmd/activable/...)
    ↓ calls
GraphQL API server (go/internal/api/...)
    ↓ calls via FFI
Rust FFI surface (crates/activable-ffi/src/query_surface.rs)
    ↓ calls
GraphClient (crates/activable-graph/src/client.rs)
    ↓ calls
CypherBuilder (crates/activable-graph/src/query_builder.rs)
    ↓ generates
Postgres + Apache AGE (execute Cypher)
```

You only need to implement the bottom three layers. The CLI and API are separate concerns.

## Step 1: Add a CypherBuilder Method

Open `crates/activable-graph/src/query_builder.rs`. This is where you write the Cypher template.

```rust
impl CypherBuilder {
    /// Count the number of principals reachable via CanAssume edges from a given principal.
    ///
    /// Returns a Cypher query that counts distinct Principal nodes reachable via
    /// one or more CanAssume edges from `start`, up to `max_hops` steps.
    pub fn count_reachable_principals(
        &self,
        start: &NodeId,
        max_hops: u8,
    ) -> Result<String, GraphError> {
        let escaped_start = escape_cypher(start.as_str());

        let cypher = format!(
            "MATCH (s {{id: '{}'}}) -[:CanAssume*1..{}]-> (t:Principal) RETURN COUNT(DISTINCT t.id)",
            escaped_start, max_hops
        );

        Ok(format!(
            "SELECT * FROM ag_catalog.cypher('{}', $${}$$) AS (count agtype)",
            self.graph_name, cypher
        ))
    }
}
```

**Pattern:**
- Add a public method to `CypherBuilder`.
- Use `escape_cypher()` on all user inputs (NodeId, strings from the API).
- Use `validate_label()` on label names (edge types, node types).
- Wrap the Cypher query in `ag_catalog.cypher('<graph_name>', $$...$$)` and cast the result column.
- Return a `Result<String, GraphError>` — the String is the full SQL statement ready to execute.
- Document the method with a docstring explaining the semantics.

**Escaping rules:**
- `escape_cypher()` — for node IDs and values that appear in Cypher string literals. **Call exactly once per value.**
- `validate_label()` — for node/edge labels. Catches invalid label names early.
- `escape_sql_literal()` — for SQL-level escaping if embedding agtype strings in SQL (rare; most queries use Cypher-level escaping).

## Step 2: Unit Test the CypherBuilder Method

Add a test in the same file (`query_builder.rs`). Tests verify the generated Cypher string, not the query results.

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_reachable_principals() {
        let builder = CypherBuilder::new("test_graph");
        let start = NodeId::new("arn:aws:iam::123456789012:role/MyRole").unwrap();

        let query = builder.count_reachable_principals(&start, 5).unwrap();

        // Verify the Cypher structure
        assert!(query.contains("MATCH (s {id: 'arn:aws:iam::123456789012:role/MyRole'})"));
        assert!(query.contains("[:CanAssume*1..5]"));
        assert!(query.contains("COUNT(DISTINCT t.id)"));
    }

    #[test]
    fn test_count_reachable_principals_escapes_quotes() {
        let builder = CypherBuilder::new("test_graph");
        let start = NodeId::new("arn:aws:iam::123456789012:role/Role'With'Quotes").unwrap();

        let query = builder.count_reachable_principals(&start, 5).unwrap();

        // Verify escaping
        assert!(query.contains("Role\\'With\\'Quotes"));
    }
}
```

**Pattern:**
- Test the generated SQL string, not the result set.
- Test normal cases and edge cases (empty labels, special characters, max depth).
- Verify that `escape_cypher()` and `validate_label()` are called (check the output string).

## Step 3: Add a GraphClient Method

Open `crates/activable-graph/src/client.rs`. This method wraps the CypherBuilder query and executes it.

```rust
impl GraphClient {
    /// Count the number of principals reachable via CanAssume edges.
    ///
    /// # Arguments
    /// * `start` - The starting principal (ARN).
    /// * `max_hops` - Maximum number of CanAssume edges to traverse.
    ///
    /// # Returns
    /// A count of distinct Principal nodes.
    pub async fn count_reachable_principals(
        &self,
        start: &NodeId,
        max_hops: u8,
    ) -> Result<u64, GraphError> {
        if max_hops == 0 {
            return Err(GraphError::InvalidParameter("max_hops must be > 0".to_string()));
        }

        let query = self.builder.count_reachable_principals(start, max_hops)?;

        let rows = self.pool.get_connection().await?
            .query(&query, &[])
            .await?;

        if rows.is_empty() {
            return Ok(0);
        }

        let agtype_value: String = rows[0].get(0);

        // Parse agtype JSON ({"int": 42} format)
        let count: u64 = parse_agtype_count(&agtype_value)?;
        Ok(count)
    }
}
```

**Streaming vs. Collected Decision:**

- **Collected** (like `count_reachable_principals` above): Use when the result set is small (< 1000 rows) or you need to post-process all results. Return a `Vec<T>` or single value.

  ```rust
  pub async fn query_name(&self, ...) -> Result<Vec<QueryResult>, GraphError> {
      let rows = self.pool.get_connection().await?
          .query(&query, &[])
          .await?;
      Ok(rows.into_iter().map(|row| parse_row(row)).collect())
  }
  ```

- **Streaming** (like `walk_edges`): Use when the result set is large (> 10k rows) or you want to process results incrementally. Return an async stream or channel.

  ```rust
  pub async fn walk_edges(
      &self,
      start: &NodeId,
      edge_types: &[&str],
      direction: Direction,
      depth_limit: u8,
  ) -> Result<impl futures::Stream<Item = Result<Node, GraphError>>, GraphError> {
      let query = self.builder.walk_edges(start, edge_types, direction, depth_limit)?;
      let conn = self.pool.get_connection().await?;
      let rows = conn.query(&query, &[]).await?;

      Ok(futures::stream::iter(rows).map(|row| {
          parse_node_from_row(&row)
      }))
  }
  ```

**Pattern:**
- Validate input parameters early (max_hops > 0, non-empty node IDs).
- Get a connection from the pool: `self.pool.get_connection().await?`
- Execute the query: `conn.query(&query, &[]).await?`
- Parse agtype results using helper functions (e.g., `parse_agtype_count`, `parse_agtype_node`).
- Return the parsed result or a stream of results.

## Step 4: Add GraphClient Unit Tests

Add tests in the same `client.rs` file (in a `#[cfg(test)]` module). These tests do NOT require a running Postgres instance (AGE_TEST_URL not set).

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_reachable_principals_validates_max_hops() {
        // Set up a mock pool or use a test double
        let client = GraphClient::new_for_test();

        let start = NodeId::new("arn:aws:iam::123456789012:role/MyRole").unwrap();

        // max_hops = 0 should error
        let result = tokio::runtime::Runtime::new().unwrap().block_on(
            client.count_reachable_principals(&start, 0)
        );

        assert!(result.is_err());
    }
}
```

## Step 5: Add Integration Tests (with AGE_TEST_URL)

Create a separate test file: `crates/activable-graph/tests/integration_count_reachable.rs`.

```rust
use activable_graph::client::GraphClient;
use activable_graph::types::NodeId;

#[tokio::test]
#[ignore] // Run only when AGE_TEST_URL is set
async fn test_count_reachable_principals_integration() {
    // Skip if AGE_TEST_URL not set
    let test_url = match std::env::var("AGE_TEST_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("Skipping integration test (AGE_TEST_URL not set)");
            return;
        }
    };

    let client = GraphClient::connect(&test_url).await.expect("connect");

    // Set up test data
    client.create_test_graph().await.expect("setup");

    // Test the query
    let start = NodeId::new("arn:aws:iam::123456789012:role/RoleA").unwrap();
    let count = client.count_reachable_principals(&start, 3)
        .await
        .expect("count_reachable_principals");

    assert_eq!(count, 2); // RoleA can assume RoleB and RoleC

    // Cleanup
    client.drop_test_graph().await.expect("cleanup");
}
```

**Pattern:**
- Gate on `AGE_TEST_URL` environment variable.
- Use `#[ignore]` so `cargo test` skips it by default; run with `AGE_TEST_URL=... cargo test -- --ignored`.
- Set up test data (create a small graph with known structure).
- Execute the query and assert the result.
- Clean up after (drop the test graph).

## Step 6: Expose via UniFFI FFI Boundary

Open `crates/activable-ffi/src/query_surface.rs`. Add a public function that wraps the GraphClient method:

```rust
/// Count the number of principals reachable via CanAssume edges.
///
/// # Arguments
/// * `connection_string` - Postgres connection string (postgres://user:pass@host/dbname).
/// * `start` - Starting principal ARN.
/// * `max_hops` - Maximum edges to traverse.
///
/// # Returns
/// The count of reachable principals, or an error string if the query fails.
pub async fn count_reachable_principals(
    connection_string: String,
    start: String,
    max_hops: u8,
) -> Result<u64, String> {
    let client = GraphClient::connect(&connection_string)
        .await
        .map_err(|e| e.to_string())?;

    let start_node = NodeId::new(&start)
        .map_err(|e| e.to_string())?;

    client.count_reachable_principals(&start_node, max_hops)
        .await
        .map_err(|e| e.to_string())
}
```

Also update `crates/activable-ffi/activable.udl` (the UniFFI interface definition):

```idl
[Async]
interface QuerySurface {
    // ... existing methods ...

    /// Count principals reachable via CanAssume edges.
    u64 count_reachable_principals(
        string connection_string,
        string start,
        u8 max_hops
    );
};
```

**Pattern:**
- Wrap the GraphClient method in a public async function.
- Accept serialized strings for complex types (NodeId, edge types).
- Return `Result<T, String>` where the error is a serialized error message.
- The UniFFI binding generator will automatically create Go bindings.

## Step 7: Add CLI Subcommand

Create a new file: `go/cmd/activable/query_count_reachable.go`.

```go
package main

import (
    "context"
    "fmt"
    "github.com/spf13/cobra"
    "github.com/activable-cloud/activable.cloud/go/internal/api"
)

var queryCountReachableCmd = &cobra.Command{
    Use:   "count-reachable <principal-arn> <max-hops>",
    Short: "Count principals reachable via CanAssume edges",
    Args:  cobra.ExactArgs(2),
    RunE: func(cmd *cobra.Command, args []string) error {
        principalArn := args[0]
        maxHops := parseUint8(args[1])

        ctx := context.Background()

        // Call the FFI-exposed function
        count, err := ffi.CountReachablePrincipals(
            ctx,
            dbURL,
            principalArn,
            maxHops,
        )
        if err != nil {
            return fmt.Errorf("count_reachable_principals: %w", err)
        }

        fmt.Printf("Reachable principals: %d\n", count)
        return nil
    },
}

func init() {
    queryCmd.AddCommand(queryCountReachableCmd)
}
```

Register it in `go/cmd/activable/root.go`:

```go
func init() {
    rootCmd.AddCommand(queryCmd)
    queryCmd.AddCommand(queryCountReachableCmd) // Add this
}
```

## Step 8: Verify and Test

Before opening a PR, run:

```bash
# Unit tests (CypherBuilder + GraphClient)
cd crates/activable-graph
cargo test

# Clippy linting
cargo clippy -- -D warnings

# FFI bindings generation
cargo build -p activable-ffi

# Go tests
cd ../../go
go test -race ./...
go vet ./...

# Integration tests (requires AGE_TEST_URL)
cd ../crates/activable-graph
AGE_TEST_URL=postgres://localhost:5432/testdb cargo test -- --ignored
```

## PR Checklist

Before opening a pull request, verify:

- [ ] **CypherBuilder method added and tested.** String-based assertion tests in `query_builder.rs`.
- [ ] **GraphClient method added and tested.** Unit tests (mocked pool) + integration tests (if applicable).
- [ ] **Both unit and integration tests pass.** Unit tests: `cargo test`. Integration: `AGE_TEST_URL=... cargo test -- --ignored`.
- [ ] **FFI binding added.** `query_surface.rs` function + `activable.udl` method signature.
- [ ] **FFI compiles.** `cargo build -p activable-ffi` with 0 errors.
- [ ] **CLI subcommand added and registered.** File under `go/cmd/activable/` + registered in `root.go`.
- [ ] **CLI tests pass.** `go test -race ./cmd/activable/...` clean.
- [ ] **No plan-taxonomy tokens.** Commit messages and doc comments contain no phase numbers, finding codes, or slice identifiers.
- [ ] **Clippy and go vet pass.** `cargo clippy -- -D warnings` and `go vet ./...` clean.
- [ ] **Documentation updated.** Add the primitive to the Query API section of `docs/system-architecture.md` (name, description, latency characteristics from benchmarks).
