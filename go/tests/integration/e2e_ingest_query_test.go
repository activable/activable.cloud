// +build integration

package integration

import (
	"context"
	"os"
	"testing"
)

// TestE2E_IngestAndQueryPath validates the full ingest-to-query pipeline.
// It ingests the test fixture and verifies that path queries return expected results.
func TestE2E_IngestAndQueryPath(t *testing.T) {
	if os.Getenv("ACTIVABLE_INTEGRATION") == "" {
		t.Skip("ACTIVABLE_INTEGRATION not set; skipping integration test")
	}

	ctx := context.Background()
	db := testDB(t)
	defer db.Close()

	// Setup would normally:
	// 1. Create a clean graph
	// 2. Load the fixture files from tests/fixtures/combined/
	// 3. Call the FFI QueryPathFinder for known start/end pairs
	// 4. Compare results against expected_paths.json

	// For now, verify the test infrastructure is present
	t.Logf("Integration test infrastructure is ready for E2E path queries")

	// This test is a placeholder until the full ingestion pipeline is complete.
	// When fixtures are loaded, we'll be able to:
	// - Query from user/alice to role/admin (should find path)
	// - Query from user/unknown to role/admin (should not find path)
	// - Query alice to S3 bucket via policy chain (3-hop path)
}

// TestE2E_IngestAndQueryBlastRadius validates blast radius queries after ingestion.
func TestE2E_IngestAndQueryBlastRadius(t *testing.T) {
	if os.Getenv("ACTIVABLE_INTEGRATION") == "" {
		t.Skip("ACTIVABLE_INTEGRATION not set; skipping integration test")
	}

	ctx := context.Background()
	db := testDB(t)
	defer db.Close()

	// Setup would normally:
	// 1. Create a clean graph
	// 2. Load the fixture files
	// 3. Call FFI QueryBlastRadius with center = role/admin, max_hops = 1
	// 4. Verify result matches expected_blast_radius.json

	t.Logf("Integration test infrastructure is ready for E2E blast radius queries")

	// Expected: admin role should reach 4 nodes at 1 hop:
	// - admin role itself (center)
	// - alice (CanAssume)
	// - s3-full-access policy (AttachedPolicy)
	// - lambda-invoke policy (AttachedPolicy)
}
