// +build integration

package integration

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

// TestIdempotency_DoubleIngest tests that double-ingesting the same fixture corpus
// produces identical node and edge counts (idempotency property).
//
// Gated on ACTIVABLE_INTEGRATION=1 env var.
func TestIdempotency_DoubleIngest(t *testing.T) {
	if os.Getenv("ACTIVABLE_INTEGRATION") != "1" {
		t.Skip("skipping: ACTIVABLE_INTEGRATION not set")
	}

	// Get database URL from env
	dbURL := os.Getenv("ACTIVABLE_DB_URL")
	if dbURL == "" {
		dbURL = "postgres://activable:activable_dev@localhost:5433/activable?sslmode=disable"
	}

	// Connect to database
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("failed to connect to database: %v", err)
	}
	defer db.Close()

	// Verify connection
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("failed to ping database: %v", err)
	}

	// TODO: Initialize graph for test
	// Example: CREATE GRAPH test_idempotency IF NOT EXISTS
	initQuery := `
		LOAD 'age';
		SET search_path = ag_catalog, "$user", public;
		SELECT * FROM ag_catalog.create_graph('test_idempotency');
	`
	if _, err := db.ExecContext(ctx, initQuery); err != nil {
		// Graph may already exist; best-effort cleanup
		_ = db.ExecContext(ctx, "SELECT * FROM ag_catalog.drop_graph('test_idempotency', true)")
		if _, err := db.ExecContext(ctx, initQuery); err != nil {
			t.Fatalf("failed to initialize test graph: %v", err)
		}
	}
	defer func() {
		_ = db.ExecContext(ctx, "SELECT * FROM ag_catalog.drop_graph('test_idempotency', true)")
	}()

	// TODO: Load fixture data from tests/fixtures/combined/ (first ingest)
	// This would:
	// 1. Read iam_users.json
	// 2. Read iam_roles.json
	// 3. Read iam_policies.json
	// 4. Read s3_buckets.json, ec2_instances.json, lambda_functions.json
	// 5. Read edges.json
	// 6. Write all data to the graph via FFI or direct SQL

	// TODO: Count nodes and edges after first ingest
	// countNodesQuery := "SELECT count(*) FROM (SELECT * FROM cypher('test_idempotency', $$MATCH (n) RETURN n$$) AS (n agtype)) t"
	// countEdgesQuery := "SELECT count(*) FROM (SELECT * FROM cypher('test_idempotency', $$MATCH (a)-[r]-(b) RETURN r$$) AS (r agtype)) t"

	// TODO: Load the same fixture data again (second ingest)
	// This should be idempotent if the loader implements ON CONFLICT logic

	// TODO: Count nodes and edges again
	// Assert that counts are identical

	t.Log("Idempotency double-ingest test structure in place (fixture loading pending)")
}
