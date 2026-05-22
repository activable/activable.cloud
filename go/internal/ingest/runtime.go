package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
)

// Runtime orchestrates the ingestion of multiple cloud services.
// It manages service registration, worker pools, region discovery, and partial-failure tracking.
type Runtime struct {
	config         *Config
	db             *sql.DB
	ingesters      map[string]Ingester
	ingestersLock  sync.RWMutex
	enabledRegions []string
	ffiWriter      FFIWriter
}

// NewRuntime creates a new ingestion runtime with the given configuration and database connection.
func NewRuntime(cfg *Config, db *sql.DB) *Runtime {
	return &Runtime{
		config:    cfg,
		db:        db,
		ingesters: make(map[string]Ingester),
		ffiWriter: &DefaultFFIWriter{},
	}
}

// NewRuntimeWithFFI creates a new runtime with a custom FFI writer (for testing).
func NewRuntimeWithFFI(cfg *Config, db *sql.DB, ffi FFIWriter) *Runtime {
	return &Runtime{
		config:    cfg,
		db:        db,
		ingesters: make(map[string]Ingester),
		ffiWriter: ffi,
	}
}

// Register adds or replaces an ingester in the registry by its Service() name.
func (r *Runtime) Register(ingester Ingester) {
	r.ingestersLock.Lock()
	defer r.ingestersLock.Unlock()
	r.ingesters[ingester.Service()] = ingester
}

// getIngesters returns a snapshot of the registered ingesters.
func (r *Runtime) getIngesters() []Ingester {
	r.ingestersLock.RLock()
	defer r.ingestersLock.RUnlock()

	ingesters := make([]Ingester, 0, len(r.ingesters))
	for _, ingester := range r.ingesters {
		ingesters = append(ingesters, ingester)
	}
	return ingesters
}

// Ingest orchestrates the ingestion of all registered services.
// Steps:
// 1. Initialize the run status table
// 2. Resolve caller identity via STS GetCallerIdentity
// 3. Discover or validate enabled regions
// 4. Call graph_initialize via FFI
// 5. Launch each ingester in parallel via errgroup
// 6. For each ingester: drain Enumerate channel, batch resources into FFI calls
// 7. Record per-service status and final run status
// Returns a combined error if any ingester failed (status will be "partial_failure" or "failed").
func (r *Runtime) Ingest(ctx context.Context) error {
	// Step 1: Initialize run status table
	if err := InitRunStatusTable(r.db); err != nil {
		return fmt.Errorf("failed to initialize run status table: %w", err)
	}

	// Step 2: Generate run ID and write initial status
	runID := uuid.New()
	initialStatus := RunStatus{
		RunID:     runID,
		StartedAt: time.Now(),
		Status:    "running",
	}
	if err := WriteRunStatus(r.db, initialStatus); err != nil {
		return fmt.Errorf("failed to write initial run status: %w", err)
	}

	// Step 3: Resolve caller identity via STS
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("LoadDefaultConfig failed: %w", err)
	}

	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("GetCallerIdentity failed: %w", err)
	}

	accountID := *identity.Account
	ctx = WithAccountID(ctx, accountID)

	// Step 4: Discover or validate enabled regions
	regions, err := r.EnabledRegions(ctx)
	if err != nil {
		return fmt.Errorf("failed to get enabled regions: %w", err)
	}

	// Step 5: Initialize graph via FFI
	graphInitErr := r.ffiWriter.GraphInitialize(
		"localhost", // TODO: extract from config
		5432,        // TODO: extract from config
		"postgres",  // TODO: extract from config
		"",          // TODO: extract from config
		"activable", // TODO: use r.config.GraphName
		r.config.PoolSize,
		r.config.GraphName,
	)
	if graphInitErr != "" {
		return fmt.Errorf("graph_initialize failed: %s", graphInitErr)
	}

	// Step 6: Launch ingesters in parallel
	ingesters := r.getIngesters()
	if len(ingesters) == 0 {
		return fmt.Errorf("no ingesters registered")
	}

	eg, egCtx := errgroup.WithContext(ctx)
	eg.SetLimit(len(ingesters))

	serviceStatuses := make(map[string]*ServiceStatus)
	var statusMu sync.Mutex

	for _, ingester := range ingesters {
		ingester := ingester // Capture for closure
		serviceName := ingester.Service()

		eg.Go(func() error {
			status := &ServiceStatus{
				Name:    serviceName,
				Status:  "completed",
				Regions: regions,
			}

			defer func() {
				statusMu.Lock()
				serviceStatuses[serviceName] = status
				statusMu.Unlock()
			}()

			// Ingest for each region (or once for global services)
			for _, region := range regions {
				resourcesChan, errorsChan := ingester.Enumerate(egCtx, region)

				// Batch resources into FFI write calls
				batch := make([]ResourceSpec, 0, r.config.BatchSize)

				for {
					select {
					case resource, ok := <-resourcesChan:
						if !ok {
							// Channel closed, flush remaining batch
							if len(batch) > 0 {
								if err := r.writeBatch(batch); err != nil {
									status.Status = "partial_failure"
									status.Error = err.Error()
									return err
								}
								status.NodeCount += int64(len(batch))
								batch = batch[:0]
							}
							goto checkErrors
						}

						batch = append(batch, resource)
						if len(batch) >= r.config.BatchSize {
							if err := r.writeBatch(batch); err != nil {
								status.Status = "partial_failure"
								status.Error = err.Error()
								return err
							}
							status.NodeCount += int64(len(batch))
							batch = batch[:0]
						}

					case err := <-errorsChan:
						if err != nil {
							status.Status = "partial_failure"
							status.Error = err.Error()
							return err
						}
					}
				}

			checkErrors:
				// Drain any remaining errors
				for err := range errorsChan {
					if err != nil {
						status.Status = "partial_failure"
						status.Error = err.Error()
						return err
					}
				}
			}

			return nil
		})
	}

	// Wait for all ingesters to complete
	ingestErr := eg.Wait()

	// Step 7: Determine final status and update run record
	var finalStatus string
	var partialFailures []string

	statusMu.Lock()
	for serviceName, svc := range serviceStatuses {
		if svc.Status == "partial_failure" || svc.Status == "failed" {
			partialFailures = append(partialFailures, serviceName)
		}
	}
	statusMu.Unlock()

	if ingestErr != nil {
		finalStatus = "partial_failure"
		if len(partialFailures) == len(ingesters) {
			finalStatus = "failed"
		}
	} else {
		if len(partialFailures) > 0 {
			finalStatus = "partial_failure"
		} else {
			finalStatus = "completed"
		}
	}

	if err := UpdateRunStatus(r.db, runID, finalStatus, partialFailures); err != nil {
		return fmt.Errorf("failed to update run status: %w", err)
	}

	return ingestErr
}

// writeBatch writes a batch of resources to the graph via FFI.
// Each resource is converted to a node; each edge is written separately.
func (r *Runtime) writeBatch(resources []ResourceSpec) error {
	// Convert resources to JSON array for FFI call
	nodesByLabel := make(map[string][]interface{})
	allEdges := make([]interface{}, 0)

	for _, resource := range resources {
		// Add to nodes batch by label
		nodeData := map[string]interface{}{
			"id":         resource.ID,
			"properties": resource.Properties,
		}
		nodesByLabel[resource.Label] = append(nodesByLabel[resource.Label], nodeData)

		// Collect edges
		for _, edge := range resource.Edges {
			edgeData := map[string]interface{}{
				"from_id":    edge.FromID,
				"to_id":      edge.ToID,
				"edge_type":  edge.EdgeType,
				"properties": edge.Properties,
			}
			allEdges = append(allEdges, edgeData)
		}
	}

	// Write nodes by label
	for label, nodes := range nodesByLabel {
		nodesJSON, err := json.Marshal(nodes)
		if err != nil {
			return fmt.Errorf("failed to marshal nodes: %w", err)
		}

		result := r.ffiWriter.AddNodesBatch(label, string(nodesJSON))
		if result != "" && !isCountResult(result) {
			// Non-empty, non-count result is an error
			return fmt.Errorf("add_nodes_batch failed: %s", result)
		}
	}

	// Write edges if any
	if len(allEdges) > 0 {
		edgesJSON, err := json.Marshal(allEdges)
		if err != nil {
			return fmt.Errorf("failed to marshal edges: %w", err)
		}

		result := r.ffiWriter.AddEdgesBatch(string(edgesJSON))
		if result != "" && !isCountResult(result) {
			return fmt.Errorf("add_edges_batch failed: %s", result)
		}
	}

	return nil
}

// isCountResult checks if a result string is a valid count JSON response like {"count": N}.
func isCountResult(result string) bool {
	var countResp map[string]interface{}
	err := json.Unmarshal([]byte(result), &countResp)
	if err != nil {
		return false
	}
	_, ok := countResp["count"]
	return ok
}
