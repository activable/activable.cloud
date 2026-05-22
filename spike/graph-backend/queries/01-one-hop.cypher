// One-hop query: Direct relationships from a principal
// AGE flavor: MATCH, WHERE, RETURN with limit
// Parameterized by start node ARN

MATCH (p:Principal {id: $1})-[r]->(t)
RETURN t
LIMIT 100
