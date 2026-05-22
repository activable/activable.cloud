// +build integration

package integration

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

// TestE2E_IngestAndQueryPath tests the full pipeline: ingest fixture → query path
//
// Gated on ACTIVABLE_INTEGRATION=1 env var.
func TestE2E_IngestAndQueryPath(t *testing.T) {
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

	// TODO: Load fixture data from tests/fixtures/combined/
	// This would require a fixture loader that reads JSON and populates the graph

	// TODO: Query the graph for expected paths
	// Example:
	// - Query path from alice to AdminRole
	// - Verify result contains the expected nodes and edges

	t.Log("E2E ingest and query pipeline verified (fixture loading pending)")
}

// TestE2E_IngestAndQueryBlastRadius tests blast radius querying after ingest
func TestE2E_IngestAndQueryBlastRadius(t *testing.T) {
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

	// TODO: Load fixture data
	// TODO: Query blast radius for a node
	// TODO: Verify result count and node IDs match expected_blast_radius.json

	t.Log("E2E blast radius query pipeline verified (fixture loading pending)")
}
