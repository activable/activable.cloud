// +build integration

package integration

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

// testDB returns a connection to the test database.
// The database URL should be provided via ACTIVABLE_DB_URL or a default localhost URL.
func testDB(t *testing.T) *sql.DB {
	t.Helper()

	dbURL := os.Getenv("ACTIVABLE_DB_URL")
	if dbURL == "" {
		dbURL = "postgresql://activable:activable_dev@localhost:5433/activable"
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	// Test the connection
	err = db.Ping()
	if err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	return db
}
