package graphql

// FFIClient defines the interface for calling Rust FFI functions.
// Implementations may require CGo linking against the Rust library.
type FFIClient interface {
	GraphInitialize(host, user, password, dbname, graphName string, maxConnections uint32) error
	QueryFindNode(label, id string) (string, error)
	QueryWalkEdges(start string, edgeTypes []string, direction string, depth uint32) (string, error)
	QueryPathFinder(start, end string, edgePattern []string, maxHops uint32) (string, error)
	QueryBlastRadius(start string, depth uint32) (string, error)
	QuerySubgraph(center string, radius uint32) (string, error)
	IngestStatus(runID string) (string, error)
	HealthCheck() (string, error)
}
