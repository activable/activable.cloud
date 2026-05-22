package ingest

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/activable-cloud/activable.cloud/bindings/activable"
)

// FFIWriter defines the interface for writing nodes and edges to the graph via FFI.
type FFIWriter interface {
	// AddNodesBatch adds a batch of nodes to the graph.
	// Returns error if the batch write fails.
	AddNodesBatch(nodes []ResourceSpec) error

	// AddEdgesBatch adds a batch of edges to the graph.
	// Returns error if the batch write fails.
	AddEdgesBatch(edges []EdgeSpec) error
}

// DefaultFFIWriter implements FFIWriter by calling the real activable_ffi functions.
type DefaultFFIWriter struct{}

// NewDefaultFFIWriter creates a new FFI writer that calls the Rust FFI layer.
func NewDefaultFFIWriter() *DefaultFFIWriter {
	return &DefaultFFIWriter{}
}

// AddNodesBatch sends a batch of nodes to the Rust FFI layer.
// Nodes are serialized as a JSON array matching the Rust contract format:
// [{"label":"Type","id":"arn:...","properties":{...}}, ...]
func (w *DefaultFFIWriter) AddNodesBatch(nodes []ResourceSpec) error {
	if len(nodes) == 0 {
		return nil
	}

	// Serialize nodes to JSON array format expected by Rust FFI
	nodeArray := make([]map[string]interface{}, 0, len(nodes))
	for _, node := range nodes {
		nodeArray = append(nodeArray, map[string]interface{}{
			"label":      node.Label,
			"id":         node.ID,
			"properties": node.Properties,
		})
	}

	nodesJSON, err := json.Marshal(nodeArray)
	if err != nil {
		return fmt.Errorf("failed to marshal nodes to JSON: %w", err)
	}

	// Call the real FFI function with the batch
	count, err := activable.AddNodesBatch(string(nodesJSON))
	if err != nil {
		return fmt.Errorf("FFI AddNodesBatch failed: %w", err)
	}

	log.Printf("[ingest] wrote %d nodes via FFI", count)
	return nil
}

// AddEdgesBatch sends a batch of edges to the Rust FFI layer.
// Edges are serialized as a JSON array matching the Rust contract format:
// [{"from_id":"...","to_id":"...","edge_type":"...","properties":{...}}, ...]
func (w *DefaultFFIWriter) AddEdgesBatch(edges []EdgeSpec) error {
	if len(edges) == 0 {
		return nil
	}

	// Serialize edges to JSON array format expected by Rust FFI
	edgeArray := make([]map[string]interface{}, 0, len(edges))
	for _, edge := range edges {
		edgeArray = append(edgeArray, map[string]interface{}{
			"from_id":    edge.FromID,
			"to_id":      edge.TargetID,
			"edge_type":  edge.EdgeType,
			"properties": edge.Properties,
		})
	}

	edgesJSON, err := json.Marshal(edgeArray)
	if err != nil {
		return fmt.Errorf("failed to marshal edges to JSON: %w", err)
	}

	// Call the real FFI function with the batch
	count, err := activable.AddEdgesBatch(string(edgesJSON))
	if err != nil {
		return fmt.Errorf("FFI AddEdgesBatch failed: %w", err)
	}

	log.Printf("[ingest] wrote %d edges via FFI", count)
	return nil
}

// GraphInitializer defines the interface for initializing the graph database.
type GraphInitializer interface {
	// Initialize sets up the graph database with the given parameters.
	Initialize(databaseURL string, poolSize int, graphName string) error
}

// DefaultGraphInitializer implements GraphInitializer by validating configuration.
// The actual graph initialization (FFI pool setup) is performed by the GraphQL server
// at startup via activable.GraphInitialize(). Ingestion runs in-process and uses
// the already-initialized pool.
type DefaultGraphInitializer struct{}

// NewDefaultGraphInitializer creates a graph initializer.
func NewDefaultGraphInitializer() *DefaultGraphInitializer {
	return &DefaultGraphInitializer{}
}

// Initialize validates the graph configuration and logs that initialization
// is handled by the server process at startup.
// The actual FFI pool initialization happens once in the server's main(),
// not in each ingestion runtime.
func (g *DefaultGraphInitializer) Initialize(databaseURL string, poolSize int, graphName string) error {
	// Validate inputs
	if databaseURL == "" {
		return fmt.Errorf("database URL cannot be empty")
	}
	if poolSize <= 0 {
		return fmt.Errorf("pool size must be positive")
	}
	if graphName == "" {
		return fmt.Errorf("graph name cannot be empty")
	}

	// Graph initialization is already handled by the server process.
	// Log this for operational clarity.
	log.Printf("[ingest] graph initialization validated (pool already initialized by server)")

	return nil
}
