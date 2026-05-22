// +build !test

package graphql

import (
	"sync"

	"github.com/activable-cloud/activable.cloud/bindings/activable"
)

// RealFFIClient wraps activable_ffi bindings with error handling.
type RealFFIClient struct {
	initOnce sync.Once
	initErr  error
}

// NewRealFFIClient creates a new RealFFIClient.
func NewRealFFIClient() *RealFFIClient {
	return &RealFFIClient{}
}

// GraphInitialize initializes the graph runtime.
func (r *RealFFIClient) GraphInitialize(host, user, password, dbname, graphName string, port uint16, maxConnections uint32) error {
	r.initOnce.Do(func() {
		r.initErr = activable.GraphInitialize(host, port, user, password, dbname, graphName, maxConnections)
	})
	return r.initErr
}

// QueryFindNode calls the Rust query_find_node function.
func (r *RealFFIClient) QueryFindNode(label, id string) (string, error) {
	return activable.QueryFindNode(label, id)
}

// QueryWalkEdges calls the Rust query_walk_edges function.
func (r *RealFFIClient) QueryWalkEdges(start string, edgeTypes []string, direction string, depth uint32) (string, error) {
	// Join edge types with commas
	edgeTypesStr := ""
	for i, et := range edgeTypes {
		if i > 0 {
			edgeTypesStr += ","
		}
		edgeTypesStr += et
	}
	return activable.QueryWalkEdges(start, edgeTypesStr, direction, depth)
}

// QueryPathFinder calls the Rust query_path_finder function.
func (r *RealFFIClient) QueryPathFinder(start, end string, edgePattern []string, maxHops uint32) (string, error) {
	// Join edge pattern with commas
	patternStr := ""
	for i, ep := range edgePattern {
		if i > 0 {
			patternStr += ","
		}
		patternStr += ep
	}
	return activable.QueryPathFinder(start, end, patternStr, maxHops)
}

// QueryBlastRadius calls the Rust query_blast_radius function.
func (r *RealFFIClient) QueryBlastRadius(start string, depth uint32) (string, error) {
	return activable.QueryBlastRadius(start, depth)
}

// QuerySubgraph calls the Rust query_subgraph function.
func (r *RealFFIClient) QuerySubgraph(center string, radius uint32) (string, error) {
	return activable.QuerySubgraph(center, radius)
}

// IngestStatus checks ingest run status (placeholder).
func (r *RealFFIClient) IngestStatus(runID string) (string, error) {
	// TODO: Implement ingest status query from database
	return "", nil
}

// HealthCheck calls the Rust health_check function.
func (r *RealFFIClient) HealthCheck() (string, error) {
	return activable.HealthCheck()
}
