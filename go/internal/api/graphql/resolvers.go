package graphql

import (
	"encoding/json"
	"fmt"
	"strings"
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
func (r *Resolver) TriggerIngest(provider string, regions []string) (*IngestRun, error) {
	// Placeholder: In a real implementation, this would spawn an async ingestion job
	// and return the IngestRun with status RUNNING.
	run := &IngestRun{
		ID:        generateRunID(),
		Status:    "RUNNING",
		StartedAt: getCurrentTimestamp(),
		Services: []IngestService{
			{
				Name:      provider,
				Status:    "RUNNING",
				NodeCount: 0,
				EdgeCount: 0,
			},
		},
	}
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

// Helper functions

func generateRunID() string {
	// In a real implementation, this would generate a unique ID
	// For now, return a placeholder
	return "run-" + fmt.Sprintf("%d", 123456789)
}

func getCurrentTimestamp() string {
	// In a real implementation, this would return the current timestamp in ISO 8601 format
	return "2025-01-01T00:00:00Z"
}

// parseErrorResponse attempts to extract an error message from FFI JSON response.
func parseErrorResponse(jsonStr string) error {
	var errObj map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &errObj); err != nil {
		return fmt.Errorf("unparseable FFI response: %s", jsonStr)
	}

	if errMsg, exists := errObj["error"]; exists {
		if msg, ok := errMsg.(string); ok {
			return fmt.Errorf("FFI error: %s", msg)
		}
	}

	return fmt.Errorf("unknown FFI error")
}

// isErrorResponse checks if a JSON response is an error.
func isErrorResponse(jsonStr string) bool {
	return strings.HasPrefix(jsonStr, "{\"error\"")
}
