package activable

import "github.com/activable-cloud/activable.cloud/bindings/activable_ffi"

// Version returns the activable schema version string from the Rust FFI.
//
// This function calls into the native Rust library (libactivable_ffi)
// via the UniFFI interface. It is thread-safe and can be called
// concurrently from multiple goroutines.
//
// The return value is the schema version in the format "activable vX.Y.Z".
func Version() string {
	return activable_ffi.Version()
}

// Graph initialization functions

// GraphInitialize initializes the global graph runtime.
func GraphInitialize(dbHost string, dbPort uint16, dbUser string, dbPassword string, dbName string, maxConnections uint32, graphName string) string {
	return activable_ffi.GraphInitialize(dbHost, dbPort, dbUser, dbPassword, dbName, maxConnections, graphName)
}

// HealthCheck checks the health of the graph database connection.
func HealthCheck() string {
	return activable_ffi.HealthCheck()
}

// Query functions

// QueryFindNode finds a node by label and ID.
func QueryFindNode(graphName string, label string, id string) string {
	return activable_ffi.QueryFindNode(graphName, label, id)
}

// QueryWalkEdges walks edges from a starting node.
func QueryWalkEdges(graphName string, startID string, edgeTypes []string, direction string, depth uint32) string {
	return activable_ffi.QueryWalkEdges(graphName, startID, edgeTypes, direction, depth)
}

// QueryPathFinder finds paths between two nodes.
func QueryPathFinder(graphName string, startID string, endID string, edgeTypes []string, maxHops uint32) string {
	return activable_ffi.QueryPathFinder(graphName, startID, endID, edgeTypes, maxHops)
}

// QueryBlastRadius computes the blast radius from a node.
func QueryBlastRadius(graphName string, nodeID string, edgeTypes []string, maxHops uint32) string {
	return activable_ffi.QueryBlastRadius(graphName, nodeID, edgeTypes, maxHops)
}

// QuerySubgraph fetches a subgraph around a center node.
func QuerySubgraph(graphName string, centerID string, radius uint32) string {
	return activable_ffi.QuerySubgraph(graphName, centerID, radius)
}
