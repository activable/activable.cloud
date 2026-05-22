package ingest

// FFIWriter provides an interface for graph write operations via FFI.
// This allows testing without requiring the full FFI library linkage.
type FFIWriter interface {
	// GraphInitialize initializes the graph runtime.
	GraphInitialize(dbHost string, dbPort uint16, dbUser string, dbPassword string, dbName string, maxConnections uint32, graphName string) string

	// AddNodesBatch writes a batch of nodes to the graph.
	AddNodesBatch(label string, nodesJSON string) string

	// AddEdgesBatch writes a batch of edges to the graph.
	AddEdgesBatch(edgesJSON string) string
}

// DefaultFFIWriter is the production FFI writer that calls the Rust FFI.
// For now, this is a stub that returns success without actually writing to the graph.
// In the full implementation, this will call activable_ffi functions.
type DefaultFFIWriter struct{}

// GraphInitialize initializes the graph (stub for now).
func (d *DefaultFFIWriter) GraphInitialize(dbHost string, dbPort uint16, dbUser string, dbPassword string, dbName string, maxConnections uint32, graphName string) string {
	// TODO: When FFI is available, call:
	// return activable_ffi.GraphInitialize(dbHost, dbPort, dbUser, dbPassword, dbName, maxConnections, graphName)
	return ""
}

// AddNodesBatch writes nodes to the graph (stub for now).
func (d *DefaultFFIWriter) AddNodesBatch(label string, nodesJSON string) string {
	// TODO: When FFI is available, call:
	// return activable_ffi.AddNodesBatch(label, nodesJSON)
	return `{"count": 0}`
}

// AddEdgesBatch writes edges to the graph (stub for now).
func (d *DefaultFFIWriter) AddEdgesBatch(edgesJSON string) string {
	// TODO: When FFI is available, call:
	// return activable_ffi.AddEdgesBatch(edgesJSON)
	return `{"count": 0}`
}
