// Three-hop attack path: User -> Role -> Policy -> Resource
// Demonstrates basic multi-hop traversal without variable-length paths
// AGE syntax: multi-step MATCH with explicit intermediate hops

MATCH (u:Principal {id: $1})-[:CanAssume]->(r:Principal)
-[:HasPermission]->(p:Policy)
RETURN p
LIMIT 100
