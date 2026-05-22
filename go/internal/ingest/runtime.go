package ingest

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
)

// Runtime orchestrates the ingestion of resources from multiple cloud providers.
// It manages provider registration, region discovery, concurrent enumeration,
// and writes results to the graph via the FFI layer.
type Runtime struct {
	config          Config
	db              *sql.DB
	ingesters       map[string]Ingester
	ingestorsLock   sync.RWMutex
	ffiWriter       FFIWriter
	graphInit       GraphInitializer
	enabledRegions  []string
	enabledRegionMu sync.Once
}

// NewRuntime creates a new ingestion runtime with the given configuration and database.
func NewRuntime(cfg Config, db *sql.DB) *Runtime {
	return &Runtime{
		config:    cfg,
		db:        db,
		ingesters: make(map[string]Ingester),
		ffiWriter: NewDefaultFFIWriter(),
		graphInit: NewDefaultGraphInitializer(),
	}
}

// NewRuntimeWithWriters creates a runtime with custom FFI and graph initializer.
// Useful for testing with mock implementations.
func NewRuntimeWithWriters(cfg Config, db *sql.DB, writer FFIWriter, init GraphInitializer) *Runtime {
	return &Runtime{
		config:    cfg,
		db:        db,
		ingesters: make(map[string]Ingester),
		ffiWriter: writer,
		graphInit: init,
	}
}

// Register registers a new ingester for a service.
// If an ingester for the same service already exists, it is replaced.
func (r *Runtime) Register(ingester Ingester) {
	r.ingestorsLock.Lock()
	defer r.ingestorsLock.Unlock()
	r.ingesters[ingester.Service()] = ingester
}

// Ingest orchestrates the full ingestion pipeline:
// 1. Initialize the graph database
// 2. Resolve caller identity and attach account ID to context
// 3. Discover enabled AWS regions
// 4. Launch each registered ingester in parallel via errgroup
// 5. Drain resource and edge channels, batch them, and write via FFI
// 6. Track partial failures and commit independent per-service results
// 7. Record run status to the metadata table
func (r *Runtime) Ingest(ctx context.Context) error {
	// Initialize run status table
	if err := InitRunStatusTable(ctx, r.db); err != nil {
		return fmt.Errorf("failed to initialize run status table: %w", err)
	}

	// Generate run ID and record start
	runID := uuid.New()
	runStatus := RunStatus{
		RunID:      runID,
		StartedAt:  time.Now(),
		Status:     "running",
		PartialFailures: []string{},
	}

	if err := WriteRunStatus(ctx, r.db, runStatus); err != nil {
		return fmt.Errorf("failed to write initial run status: %w", err)
	}

	// Initialize the graph database
	if err := r.graphInit.Initialize(r.config.DatabaseURL, r.config.PoolSize, r.config.GraphName); err != nil {
		return fmt.Errorf("failed to initialize graph: %w", err)
	}

	// Resolve caller identity via STS
	awsConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	stsClient := sts.NewFromConfig(awsConfig)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("failed to get caller identity: %w", err)
	}

	accountID := ""
	if identity.Account != nil {
		accountID = *identity.Account
	}

	ctx = WithAccountID(ctx, accountID)

	// Discover enabled regions
	enabledRegions, err := EnabledRegions(ctx, r.config.Regions)
	if err != nil {
		return fmt.Errorf("failed to discover regions: %w", err)
	}

	r.enabledRegions = enabledRegions

	// Get list of ingesters
	r.ingestorsLock.RLock()
	ingesters := make([]Ingester, 0, len(r.ingesters))
	for _, ingester := range r.ingesters {
		ingesters = append(ingesters, ingester)
	}
	r.ingestorsLock.RUnlock()

	if len(ingesters) == 0 {
		return fmt.Errorf("no ingesters registered")
	}

	// Launch ingesters in parallel with errgroup
	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(len(ingesters))

	partialFailuresMu := sync.Mutex{}
	var partialFailures []string

	for _, ingester := range ingesters {
		ingester := ingester // Capture for closure
		eg.Go(func() error {
			serviceName := ingester.Service()
			resourcesChan, errorsChan := ingester.Enumerate(egCtx)

			// Batch resources and write to graph
			batch := make([]ResourceSpec, 0, r.config.BatchSize)

			for {
				select {
				case resource, ok := <-resourcesChan:
					if !ok {
						// Channel closed, flush final batch
						if len(batch) > 0 {
							if err := r.ffiWriter.AddNodesBatch(batch); err != nil {
								log.Printf("failed to write final batch for service %s: %v", serviceName, err)
								partialFailuresMu.Lock()
								partialFailures = append(partialFailures, serviceName)
								partialFailuresMu.Unlock()
								return nil // Continue with other ingesters
							}
						}
						return nil
					}

					batch = append(batch, resource)
					if len(batch) >= r.config.BatchSize {
						if err := r.ffiWriter.AddNodesBatch(batch); err != nil {
							log.Printf("failed to write batch for service %s: %v", serviceName, err)
							partialFailuresMu.Lock()
							partialFailures = append(partialFailures, serviceName)
							partialFailuresMu.Unlock()
							// Drain remaining resources to clean up the channel
							for range resourcesChan {
							}
							return nil
						}
						batch = make([]ResourceSpec, 0, r.config.BatchSize)
					}

				case err := <-errorsChan:
					if err != nil {
						log.Printf("error from ingester %s: %v", serviceName, err)
						partialFailuresMu.Lock()
						partialFailures = append(partialFailures, serviceName)
						partialFailuresMu.Unlock()
					}
				}
			}
		})
	}

	// Wait for all ingesters to complete
	if err := eg.Wait(); err != nil {
		return fmt.Errorf("ingestion failed: %w", err)
	}

	// Determine final status
	finalStatus := "success"
	if len(partialFailures) > 0 {
		finalStatus = "partial_failure"
	}

	// Update run status with completion info
	if err := UpdateRunStatus(ctx, r.db, runID, finalStatus, partialFailures); err != nil {
		return fmt.Errorf("failed to update run status: %w", err)
	}

	if len(partialFailures) > 0 {
		log.Printf("ingestion completed with partial failures: %v", partialFailures)
	}

	return nil
}
