package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// RunStatus tracks the status of an ingestion run.
type RunStatus struct {
	RunID            uuid.UUID `json:"run_id"`
	StartedAt        time.Time `json:"started_at"`
	FinishedAt       time.Time `json:"finished_at"`
	Status           string    `json:"status"`
	PartialFailures  []string  `json:"partial_failures"`
}

// InitRunStatusTable creates the ingest_runs table if it doesn't exist.
// This uses plain Postgres SQL (not AGE graph) for metadata storage.
func InitRunStatusTable(ctx context.Context, db *sql.DB) error {
	schema := `
		CREATE TABLE IF NOT EXISTS ingest_runs (
			run_id UUID PRIMARY KEY,
			started_at TIMESTAMPTZ NOT NULL,
			finished_at TIMESTAMPTZ,
			status TEXT NOT NULL,
			partial_failures JSONB DEFAULT '[]'::JSONB
		);

		CREATE INDEX IF NOT EXISTS idx_ingest_runs_status ON ingest_runs(status);
	`

	_, err := db.ExecContext(ctx, schema)
	if err != nil {
		return fmt.Errorf("failed to initialize run status table: %w", err)
	}

	return nil
}

// WriteRunStatus inserts a new ingest run record at the start of ingestion.
func WriteRunStatus(ctx context.Context, db *sql.DB, rs RunStatus) error {
	failuresJSON, err := json.Marshal(rs.PartialFailures)
	if err != nil {
		return fmt.Errorf("failed to marshal partial failures: %w", err)
	}

	query := `
		INSERT INTO ingest_runs (run_id, started_at, status, partial_failures)
		VALUES ($1, $2, $3, $4)
	`

	_, err = db.ExecContext(ctx, query, rs.RunID, rs.StartedAt, rs.Status, failuresJSON)
	if err != nil {
		return fmt.Errorf("failed to write run status: %w", err)
	}

	return nil
}

// UpdateRunStatus updates the run record with completion time and final status.
func UpdateRunStatus(ctx context.Context, db *sql.DB, runID uuid.UUID, status string, partialFailures []string) error {
	failuresJSON, err := json.Marshal(partialFailures)
	if err != nil {
		return fmt.Errorf("failed to marshal partial failures: %w", err)
	}

	query := `
		UPDATE ingest_runs
		SET finished_at = NOW(), status = $1, partial_failures = $2
		WHERE run_id = $3
	`

	result, err := db.ExecContext(ctx, query, status, failuresJSON, runID)
	if err != nil {
		return fmt.Errorf("failed to update run status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no run found with ID %s", runID)
	}

	return nil
}
