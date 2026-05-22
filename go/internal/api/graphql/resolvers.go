package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/activable-cloud/activable.cloud/go/internal/ingest"
	"github.com/activable-cloud/activable.cloud/go/internal/ingest/aws"
	awspkg "github.com/activable-cloud/activable.cloud/go/pkg/aws"
)

// Resolver provides GraphQL resolver implementations.
type Resolver struct {
	ffi FFIClient
}

// NewResolver creates a new Resolver with the given FFI client.
func NewResolver(ffi FFIClient) *Resolver {
	return &Resolver{ffi: ffi}
}

// NodeRef represents a graph node reference.
type NodeRef struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// Node represents a full graph node with properties.
type Node struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Properties string `json:"properties,omitempty"`
}

// Path represents a path between two nodes.
type Path struct {
	Nodes  []NodeRef `json:"nodes"`
	Edges  []Edge    `json:"edges"`
	Length int       `json:"length"`
}

// Edge represents a directed edge between nodes.
type Edge struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Type       string `json:"type"`
	Properties string `json:"properties,omitempty"`
}

// Subgraph represents a subgraph centered on a node.
type Subgraph struct {
	Center NodeRef   `json:"center"`
	Nodes  []NodeRef `json:"nodes"`
}

// IngestService represents a single service in an ingest run.
type IngestService struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	NodeCount int    `json:"node_count"`
	EdgeCount int    `json:"edge_count"`
	Error     string `json:"error,omitempty"`
}

// IngestRun represents an asynchronous ingestion job.
type IngestRun struct {
	ID        string           `json:"id"`
	Status    string           `json:"status"`
	StartedAt string           `json:"started_at"`
	Services  []IngestService  `json:"services"`
}

// FindNode resolves the findNode query.
func (r *Resolver) FindNode(label, id string) (*Node, error) {
	result, err := r.ffi.QueryFindNode(label, id)
	if err != nil {
		return nil, fmt.Errorf("query find node failed: %w", err)
	}

	if result == "null" {
		return nil, nil
	}

	var nodeRef NodeRef
	if err := json.Unmarshal([]byte(result), &nodeRef); err != nil {
		return nil, fmt.Errorf("failed to parse node response: %w", err)
	}

	return &Node{
		ID:    nodeRef.ID,
		Label: nodeRef.Label,
	}, nil
}

// WalkEdges resolves the walkEdges query.
func (r *Resolver) WalkEdges(start string, edgeTypes []string, direction string, depth int) ([]*NodeRef, error) {
	result, err := r.ffi.QueryWalkEdges(start, edgeTypes, direction, uint32(depth))
	if err != nil {
		return nil, fmt.Errorf("query walk edges failed: %w", err)
	}

	var nodes []NodeRef
	if err := json.Unmarshal([]byte(result), &nodes); err != nil {
		return nil, fmt.Errorf("failed to parse walk edges response: %w", err)
	}

	// Convert to pointers
	result_ptrs := make([]*NodeRef, len(nodes))
	for i := range nodes {
		result_ptrs[i] = &nodes[i]
	}

	return result_ptrs, nil
}

// PathFinder resolves the pathFinder query.
func (r *Resolver) PathFinder(start, end string, edgePattern []string, maxHops int) ([]*Path, error) {
	result, err := r.ffi.QueryPathFinder(start, end, edgePattern, uint32(maxHops))
	if err != nil {
		return nil, fmt.Errorf("query path finder failed: %w", err)
	}

	var paths []Path
	if err := json.Unmarshal([]byte(result), &paths); err != nil {
		return nil, fmt.Errorf("failed to parse path finder response: %w", err)
	}

	// Convert to pointers
	result_ptrs := make([]*Path, len(paths))
	for i := range paths {
		result_ptrs[i] = &paths[i]
	}

	return result_ptrs, nil
}

// BlastRadius resolves the blastRadius query.
func (r *Resolver) BlastRadius(node string, depth int) ([]*NodeRef, error) {
	result, err := r.ffi.QueryBlastRadius(node, uint32(depth))
	if err != nil {
		return nil, fmt.Errorf("query blast radius failed: %w", err)
	}

	var nodes []NodeRef
	if err := json.Unmarshal([]byte(result), &nodes); err != nil {
		return nil, fmt.Errorf("failed to parse blast radius response: %w", err)
	}

	// Convert to pointers
	result_ptrs := make([]*NodeRef, len(nodes))
	for i := range nodes {
		result_ptrs[i] = &nodes[i]
	}

	return result_ptrs, nil
}

// Subgraph resolves the subgraph query.
func (r *Resolver) Subgraph(center string, radius int) (*Subgraph, error) {
	result, err := r.ffi.QuerySubgraph(center, uint32(radius))
	if err != nil {
		return nil, fmt.Errorf("query subgraph failed: %w", err)
	}

	var sg Subgraph
	if err := json.Unmarshal([]byte(result), &sg); err != nil {
		return nil, fmt.Errorf("failed to parse subgraph response: %w", err)
	}

	return &sg, nil
}

// IngestStatus resolves the ingestStatus query.
func (r *Resolver) IngestStatus(runID string) (*IngestRun, error) {
	result, err := r.ffi.IngestStatus(runID)
	if err != nil {
		return nil, fmt.Errorf("ingest status failed: %w", err)
	}

	if result == "" {
		return nil, nil
	}

	var run IngestRun
	if err := json.Unmarshal([]byte(result), &run); err != nil {
		return nil, fmt.Errorf("failed to parse ingest run response: %w", err)
	}

	return &run, nil
}

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

// Healthz resolves the healthz query.
func (r *Resolver) Healthz() (string, error) {
	result, err := r.ffi.HealthCheck()
	if err != nil {
		return "error", fmt.Errorf("health check failed: %w", err)
	}
	return result, nil
}

// Helper functions removed — real implementations inline in TriggerIngest.
