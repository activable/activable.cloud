// Six-hop variable-length path (CRITICAL PERF TEST)
// Tests AGE's documented performance cliff on deep variable-length traversals
// [r*1..6] syntax: variable-length edges between 1 and 6 hops
// This is the primary benchmark for go/no-go gate

MATCH p = (s:Principal {id: $1})-[:CanAssume|HasPermission*1..6]->(t:Principal)
RETURN t
LIMIT 50
