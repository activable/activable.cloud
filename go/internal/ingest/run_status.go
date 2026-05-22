package ingest

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// InitRunStatusTable creates the ingest_runs metadata table if it doesn't already exist.
// This is idempotent and safe to call multiple times.
func InitRunStatusTable(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS ingest_runs (
		run_id UUID PRIMARY KEY,
		started_at TIMESTAMPTZ NOT NULL,
		finished_at TIMESTAMPTZ,
		status TEXT NOT NULL,
		partial_failures JSONB
	);
	`

	_, err := db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create ingest_runs table: %w", err)
	}

	return nil
}

// WriteRunStatus inserts a new ingest_runs record at the start of a run.
func WriteRunStatus(db *sql.DB, rs RunStatus) error {
	failuresJSON, err := json.Marshal(rs.PartialFailures)
	if err != nil {
		return fmt.Errorf("failed to marshal partial_failures: %w", err)
	}

	query := `
	INSERT INTO ingest_runs (run_id, started_at, finished_at, status, partial_failures)
	VALUES ($1, $2, $3, $4, $5)
	`

	_, err = db.Exec(query,
		rs.RunID,
		rs.StartedAt,
		rs.FinishedAt,
		rs.Status,
		failuresJSON,
	)
	if err != nil {
		return fmt.Errorf("failed to write run status: %w", err)
	}

	return nil
}

// UpdateRunStatus updates an existing ingest_runs record with final status.
func UpdateRunStatus(db *sql.DB, runID uuid.UUID, status string, partials []string) error {
	failuresJSON, err := json.Marshal(partials)
	if err != nil {
		return fmt.Errorf("failed to marshal partial_failures: %w", err)
	}

	query := `
	UPDATE ingest_runs
	SET finished_at = NOW(), status = $1, partial_failures = $2
	WHERE run_id = $3
	`

	result, err := db.Exec(query, status, failuresJSON, runID)
	if err != nil {
		return fmt.Errorf("failed to update run status: %w", err)
	}

	// Check that exactly one row was updated
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected != 1 {
		return fmt.Errorf("expected 1 row to be updated, got %d", rowsAffected)
	}

	return nil
}

// GetRunStatus retrieves a run status record by ID.
func GetRunStatus(db *sql.DB, runID uuid.UUID) (*RunStatus, error) {
	var rs RunStatus
	var failuresJSON []byte

	query := `
	SELECT run_id, started_at, finished_at, status, partial_failures
	FROM ingest_runs
	WHERE run_id = $1
	`

	err := db.QueryRow(query, runID).Scan(
		&rs.RunID,
		&rs.StartedAt,
		&rs.FinishedAt,
		&rs.Status,
		&failuresJSON,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // Record not found
		}
		return nil, fmt.Errorf("failed to query run status: %w", err)
	}

	// Unmarshal partial failures if present
	if len(failuresJSON) > 0 {
		err = json.Unmarshal(failuresJSON, &rs.PartialFailures)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal partial_failures: %w", err)
		}
	}

	return &rs, nil
}

// arrayToJSONB converts a string array to JSONB for Postgres storage.
// Used internally for pq.Array conversion if needed.
func arrayToJSONB(arr []string) interface{} {
	if len(arr) == 0 {
		return nil
	}
	return pq.Array(arr)
}
