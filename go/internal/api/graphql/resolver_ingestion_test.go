//go:build test

package graphql

import (
	"fmt"
	"time"
)

// TriggerIngest is a test stub that returns a pending ingestion run without executing ingestion.
func (r *Resolver) TriggerIngest(provider string, regions []string) (*IngestRun, error) {
	runID := fmt.Sprintf("run-%d", time.Now().UnixNano())
	startedAt := time.Now().UTC().Format(time.RFC3339)

	// Build service list from requested regions
	services := make([]IngestService, 0, 5)
	for _, svc := range []string{"iam", "sts", "s3", "ec2", "lambda"} {
		services = append(services, IngestService{
			Name:   svc,
			Status: "PENDING",
		})
	}

	run := &IngestRun{
		ID:        runID,
		Status:    "RUNNING",
		StartedAt: startedAt,
		Services:  services,
	}

	// Note: In tests, we don't spawn real ingestion. The real implementation is in resolver_ingestion.go.

	return run, nil
}
