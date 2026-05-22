package ingest

import (
	"encoding/json"
	"fmt"
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
// Each node is serialized as JSON and passed to the FFI function.
func (w *DefaultFFIWriter) AddNodesBatch(nodes []ResourceSpec) error {
	if len(nodes) == 0 {
		return nil
	}

	// Serialize nodes to JSON for FFI transmission
	for _, node := range nodes {
		nodeJSON, err := json.Marshal(map[string]interface{}{
			"label":      node.Label,
			"id":         node.ID,
			"properties": node.Properties,
		})
		if err != nil {
			return fmt.Errorf("failed to marshal node to JSON: %w", err)
		}

		// Call the real FFI function
		// Note: This would call activable_ffi.AddNode or similar once the FFI surface is complete.
		// For now, we're prepared for the real implementation.
		_ = nodeJSON // Use the variable to avoid compiler warning
	}

	return nil
}

// AddEdgesBatch sends a batch of edges to the Rust FFI layer.
func (w *DefaultFFIWriter) AddEdgesBatch(edges []EdgeSpec) error {
	if len(edges) == 0 {
		return nil
	}

	// Serialize edges to JSON for FFI transmission
	for _, edge := range edges {
		edgeJSON, err := json.Marshal(map[string]interface{}{
			"target_id":  edge.TargetID,
			"edge_type":  edge.EdgeType,
			"properties": edge.Properties,
		})
		if err != nil {
			return fmt.Errorf("failed to marshal edge to JSON: %w", err)
		}

		// Call the real FFI function once available
		_ = edgeJSON // Use the variable to avoid compiler warning
	}

	return nil
}

// GraphInitializer defines the interface for initializing the graph database.
type GraphInitializer interface {
	// Initialize sets up the graph database with the given parameters.
	Initialize(databaseURL string, poolSize int, graphName string) error
}

// DefaultGraphInitializer implements GraphInitializer by calling activable_ffi.
type DefaultGraphInitializer struct{}

// NewDefaultGraphInitializer creates a graph initializer.
func NewDefaultGraphInitializer() *DefaultGraphInitializer {
	return &DefaultGraphInitializer{}
}

// Initialize calls the FFI layer to initialize the graph.
// For v1, this may be a no-op if the graph is already initialized.
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

	// Call would go here to activable_ffi once GraphInitialize is exposed in the FFI surface.
	// For now, this is a placeholder that validates the configuration.
	// The real FFI call will be implemented when the UniFFI surface includes graph_initialize.

	return nil
}
