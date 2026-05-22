//go:build !test

package graphql

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"github.com/activable-cloud/activable.cloud/go/internal/ingest/aws"
	awspkg "github.com/activable-cloud/activable.cloud/go/pkg/aws"
)

// TriggerIngest resolves the triggerIngest mutation.
// Spawns a REAL ingestion goroutine using the Go ingestion framework.
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

	// Spawn real ingestion in background goroutine
	go func() {
		// 30-minute timeout prevents orphaned goroutines on long-running ingestion
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		// Load AWS config with endpoint override (for floci in dev)
		awsCfg, err := awspkg.LoadConfig(ctx)
		if err != nil {
			log.Printf("[ingest:%s] ERROR: failed to load AWS config: %v", runID, err)
			return
		}

		// Determine regions
		ingestRegions := regions
		if len(ingestRegions) == 0 {
			ingestRegions = []string{"us-east-1"}
		}

		// Register all AWS ingesters
		allIngesters, err := aws.RegisterAllIngesters(ctx, awsCfg, ingestRegions)
		if err != nil {
			log.Printf("[ingest:%s] ERROR: failed to register ingesters: %v", runID, err)
			return
		}

		// Create runtime and register ingesters
		cfg := ingest.Config{
			GraphName: "cloud",
			BatchSize: 500,
			Regions:   ingestRegions,
		}
		// nil DB — run status tracking disabled; graph writes go through FFI
		rt := ingest.NewRuntime(cfg, nil)
		for serviceName, serviceIngesters := range allIngesters {
			for _, ingester := range serviceIngesters {
				rt.Register(ingester)
				log.Printf("[ingest:%s] Registered %s ingester", runID, serviceName)
			}
		}

		// Run ingestion
		log.Printf("[ingest:%s] Starting ingestion pipeline (%d ingesters)...", runID, len(allIngesters))
		if err := rt.Ingest(ctx); err != nil {
			log.Printf("[ingest:%s] ERROR: ingestion failed: %v", runID, err)
			return
		}
		log.Printf("[ingest:%s] Ingestion completed successfully", runID)
	}()

	return run, nil
}
