// +build integration

package integration

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"github.com/activable-cloud/activable.cloud/go/internal/ingest/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

// countGraphEntities returns the total count of nodes and edges in the graph.
func countGraphEntities(t *testing.T, db *sql.DB, graphName string) (nodeCount int64, edgeCount int64) {
	t.Helper()

	// Query node count
	var nodes int64
	err := db.QueryRow(`
		SELECT COUNT(*) FROM ag_catalog.ag_vertex
		WHERE graph_id = (SELECT oid FROM ag_catalog.ag_graph WHERE name = $1)
	`, graphName).Scan(&nodes)
	if err != nil {
		t.Fatalf("Failed to count nodes: %v", err)
	}

	// Query edge count
	var edges int64
	err = db.QueryRow(`
		SELECT COUNT(*) FROM ag_catalog.ag_edge
		WHERE graph_id = (SELECT oid FROM ag_catalog.ag_graph WHERE name = $1)
	`, graphName).Scan(&edges)
	if err != nil {
		t.Fatalf("Failed to count edges: %v", err)
	}

	return nodes, edges
}

// TestIdempotency_DoubleIngest verifies that ingesting the same fixture twice
// produces identical graph state (no duplicate nodes or edges).
func TestIdempotency_DoubleIngest(t *testing.T) {
	if os.Getenv("ACTIVABLE_INTEGRATION") == "" {
		t.Skip("ACTIVABLE_INTEGRATION not set; skipping integration test")
	}

	ctx := context.Background()
	db := testDB(t)
	defer db.Close()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatalf("Failed to load AWS config: %v", err)
	}

	graphName := "test_idempotency_graph"
	accountID := "123456789012"

	// Create runtime and register AWS ingesters
	runtime := ingest.NewRuntime(&ingest.Config{
		GraphName: graphName,
	}, db)

	err = aws.RegisterAll(ctx, runtime, cfg, accountID)
	if err != nil {
		t.Fatalf("Failed to register ingesters: %v", err)
	}

	// First ingest pass
	err = runtime.Ingest(ctx)
	if err != nil {
		t.Fatalf("First ingest failed: %v", err)
	}

	nodeCount1, edgeCount1 := countGraphEntities(t, db, graphName)

	// Second ingest pass (same fixture)
	err = runtime.Ingest(ctx)
	if err != nil {
		t.Fatalf("Second ingest failed: %v", err)
	}

	nodeCount2, edgeCount2 := countGraphEntities(t, db, graphName)

	// Assert idempotency: counts must be identical
	if nodeCount1 != nodeCount2 {
		t.Errorf("Node count mismatch: first=%d, second=%d", nodeCount1, nodeCount2)
	}

	if edgeCount1 != edgeCount2 {
		t.Errorf("Edge count mismatch: first=%d, second=%d", edgeCount1, edgeCount2)
	}

	if nodeCount1 == nodeCount2 && edgeCount1 == edgeCount2 {
		t.Logf("Idempotency verified: nodes=%d, edges=%d", nodeCount1, edgeCount1)
	}
}
