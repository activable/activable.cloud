// Subgraph extraction around a high-value node
// 1-hop to 3-hop neighborhood of a principal
// Tests graph projection and neighborhood queries

MATCH (p:Principal {id: $1})-[r:CanAssume|HasPermission*1..3]-(neighbor)
RETURN neighbor
LIMIT 100
