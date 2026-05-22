package activable

import "github.com/activable-cloud/activable.cloud/bindings/activable_ffi"

// Version returns the activable schema version string from the Rust FFI.
func Version() string {
	return activable_ffi.Version()
}

// GraphInitialize initializes the graph runtime.
func GraphInitialize(host string, port uint16, user, password, dbname, graphName string, maxConnections uint32) error {
	return activable_ffi.GraphInitialize(host, port, user, password, dbname, graphName, maxConnections)
}

// QueryFindNode finds a node by label and ID.
func QueryFindNode(label, id string) (string, error) {
	return activable_ffi.QueryFindNode(label, id)
}

// QueryWalkEdges walks edges from a starting node.
func QueryWalkEdges(start, edgeTypes, direction string, depth uint32) (string, error) {
	return activable_ffi.QueryWalkEdges(start, edgeTypes, direction, depth)
}

// QueryPathFinder finds paths between two nodes.
func QueryPathFinder(start, end, edgePattern string, maxHops uint32) (string, error) {
	return activable_ffi.QueryPathFinder(start, end, edgePattern, maxHops)
}

// QueryBlastRadius finds all nodes reachable within N hops.
func QueryBlastRadius(start string, depth uint32) (string, error) {
	return activable_ffi.QueryBlastRadius(start, depth)
}

// QuerySubgraph extracts a subgraph centered on a node.
func QuerySubgraph(center string, radius uint32) (string, error) {
	return activable_ffi.QuerySubgraph(center, radius)
}

// HealthCheck checks the health of the database connection.
func HealthCheck() (string, error) {
	return activable_ffi.HealthCheck()
}

// AddNode adds a single node to the graph.
func AddNode(label, id, propertiesJson string) error {
	return activable_ffi.AddNode(label, id, propertiesJson)
}

// AddNodesBatch adds a batch of nodes to the graph from a JSON array.
func AddNodesBatch(nodesJson string) (uint32, error) {
	return activable_ffi.AddNodesBatch(nodesJson)
}

// AddEdge adds a single edge to the graph.
func AddEdge(fromId, toId, edgeType, propertiesJson string) error {
	return activable_ffi.AddEdge(fromId, toId, edgeType, propertiesJson)
}

// AddEdgesBatch adds a batch of edges to the graph from a JSON array.
func AddEdgesBatch(edgesJson string) (uint32, error) {
	return activable_ffi.AddEdgesBatch(edgesJson)
}

// Flush commits any pending operations to the database.
func Flush() error {
	return activable_ffi.Flush()
}
