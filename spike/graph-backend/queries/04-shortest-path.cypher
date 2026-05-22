// Shortest-path query (SECOND CRITICAL PERF TEST)
// Finds the shortest path between two principals
// AGE uses iterative deepening or BFS; no native shortestPath() like Neo4j
// This is the second go/no-go gate: p95 < 3s

MATCH (s:Principal {id: $1}), (t:Principal)
WHERE t.id LIKE 'principal_%'
MATCH p = shortestPath((s)-[*1..8]-(t))
RETURN LENGTH(p) as distance
LIMIT 10
