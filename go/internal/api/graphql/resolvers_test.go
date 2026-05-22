package graphql

import (
	"testing"
)

// MockFFIClient is a mock implementation of FFIClient for testing.
// It does not require any CGo linking and can be used in pure-Go tests.
type MockFFIClient struct {
	QueryFindNodeResult        string
	QueryFindNodeErr           error
	QueryWalkEdgesResult       string
	QueryWalkEdgesErr          error
	QueryPathFinderResult      string
	QueryPathFinderErr         error
	QueryBlastRadiusResult     string
	QueryBlastRadiusErr        error
	QuerySubgraphResult        string
	QuerySubgraphErr           error
	IngestStatusResult         string
	IngestStatusErr            error
	HealthCheckResult          string
	HealthCheckErr             error
	GraphInitializeErr         error
	GraphInitializeHost        string
	GraphInitializeUser        string
	GraphInitializeDBName      string
}

func (m *MockFFIClient) GraphInitialize(host, user, password, dbname, graphName string, maxConnections uint32) error {
	m.GraphInitializeHost = host
	m.GraphInitializeUser = user
	m.GraphInitializeDBName = dbname
	return m.GraphInitializeErr
}

func (m *MockFFIClient) QueryFindNode(label, id string) (string, error) {
	return m.QueryFindNodeResult, m.QueryFindNodeErr
}

func (m *MockFFIClient) QueryWalkEdges(start string, edgeTypes []string, direction string, depth uint32) (string, error) {
	return m.QueryWalkEdgesResult, m.QueryWalkEdgesErr
}

func (m *MockFFIClient) QueryPathFinder(start, end string, edgePattern []string, maxHops uint32) (string, error) {
	return m.QueryPathFinderResult, m.QueryPathFinderErr
}

func (m *MockFFIClient) QueryBlastRadius(start string, depth uint32) (string, error) {
	return m.QueryBlastRadiusResult, m.QueryBlastRadiusErr
}

func (m *MockFFIClient) QuerySubgraph(center string, radius uint32) (string, error) {
	return m.QuerySubgraphResult, m.QuerySubgraphErr
}

func (m *MockFFIClient) IngestStatus(runID string) (string, error) {
	return m.IngestStatusResult, m.IngestStatusErr
}

func (m *MockFFIClient) HealthCheck() (string, error) {
	return m.HealthCheckResult, m.HealthCheckErr
}

// Test FindNode with valid response
func TestFindNode_Success(t *testing.T) {
	mock := &MockFFIClient{
		QueryFindNodeResult: `{"id":"node1","label":"EC2"}`,
	}
	resolver := NewResolver(mock)

	node, err := resolver.FindNode("EC2", "node1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if node == nil {
		t.Fatalf("expected node, got nil")
	}

	if node.ID != "node1" || node.Label != "EC2" {
		t.Errorf("unexpected node: %+v", node)
	}
}

// Test FindNode with null response
func TestFindNode_NotFound(t *testing.T) {
	mock := &MockFFIClient{
		QueryFindNodeResult: "null",
	}
	resolver := NewResolver(mock)

	node, err := resolver.FindNode("EC2", "nonexistent")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if node != nil {
		t.Errorf("expected nil, got %+v", node)
	}
}

// Test FindNode with FFI error
func TestFindNode_Error(t *testing.T) {
	mock := &MockFFIClient{
		QueryFindNodeErr: ErrNotInitialized,
	}
	resolver := NewResolver(mock)

	node, err := resolver.FindNode("EC2", "node1")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if node != nil {
		t.Errorf("expected nil, got %+v", node)
	}
}

// Test WalkEdges with valid response
func TestWalkEdges_Success(t *testing.T) {
	mock := &MockFFIClient{
		QueryWalkEdgesResult: `[{"id":"node2","label":"IAM"},{"id":"node3","label":"S3"}]`,
	}
	resolver := NewResolver(mock)

	nodes, err := resolver.WalkEdges("node1", []string{"ALLOW"}, "outgoing", 2)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(nodes))
	}

	if nodes[0].ID != "node2" || nodes[0].Label != "IAM" {
		t.Errorf("unexpected first node: %+v", nodes[0])
	}
}

// Test WalkEdges with empty result
func TestWalkEdges_Empty(t *testing.T) {
	mock := &MockFFIClient{
		QueryWalkEdgesResult: "[]",
	}
	resolver := NewResolver(mock)

	nodes, err := resolver.WalkEdges("node1", []string{"ALLOW"}, "outgoing", 2)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(nodes))
	}
}

// Test PathFinder with valid response
func TestPathFinder_Success(t *testing.T) {
	mock := &MockFFIClient{
		QueryPathFinderResult: `[{"nodes":[{"id":"a","label":"A"},{"id":"b","label":"B"}],"edges":[],"length":1}]`,
	}
	resolver := NewResolver(mock)

	paths, err := resolver.PathFinder("a", "b", []string{"ALLOW"}, 3)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(paths) != 1 {
		t.Errorf("expected 1 path, got %d", len(paths))
	}

	if paths[0].Length != 1 {
		t.Errorf("expected path length 1, got %d", paths[0].Length)
	}
}

// Test BlastRadius with valid response
func TestBlastRadius_Success(t *testing.T) {
	mock := &MockFFIClient{
		QueryBlastRadiusResult: `[{"id":"n1","label":"L1"},{"id":"n2","label":"L2"}]`,
	}
	resolver := NewResolver(mock)

	nodes, err := resolver.BlastRadius("center", 2)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(nodes))
	}
}

// Test Subgraph with valid response
func TestSubgraph_Success(t *testing.T) {
	mock := &MockFFIClient{
		QuerySubgraphResult: `{"center":{"id":"c","label":"Center"},"nodes":[{"id":"n1","label":"N1"}]}`,
	}
	resolver := NewResolver(mock)

	sg, err := resolver.Subgraph("c", 1)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if sg.Center.ID != "c" {
		t.Errorf("unexpected center: %+v", sg.Center)
	}

	if len(sg.Nodes) != 1 {
		t.Errorf("expected 1 node, got %d", len(sg.Nodes))
	}
}

// Test TriggerIngest
func TestTriggerIngest_Success(t *testing.T) {
	mock := &MockFFIClient{}
	resolver := NewResolver(mock)

	run, err := resolver.TriggerIngest("AWS", []string{"us-east-1"})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if run.Status != "RUNNING" {
		t.Errorf("expected status RUNNING, got %s", run.Status)
	}

	if len(run.Services) != 1 {
		t.Errorf("expected 1 service, got %d", len(run.Services))
	}
}

// Test Healthz success
func TestHealthz_Success(t *testing.T) {
	mock := &MockFFIClient{
		HealthCheckResult: "ok",
	}
	resolver := NewResolver(mock)

	status, err := resolver.Healthz()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if status != "ok" {
		t.Errorf("expected 'ok', got %s", status)
	}
}

// Test Healthz failure
func TestHealthz_Failure(t *testing.T) {
	mock := &MockFFIClient{
		HealthCheckErr: ErrNotInitialized,
	}
	resolver := NewResolver(mock)

	status, err := resolver.Healthz()
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	if status != "error" {
		t.Errorf("expected 'error', got %s", status)
	}
}

// Test IngestStatus with valid response
func TestIngestStatus_Success(t *testing.T) {
	mock := &MockFFIClient{
		IngestStatusResult: `{"id":"run1","status":"COMPLETED","started_at":"2025-01-01T00:00:00Z","services":[{"name":"aws","status":"COMPLETED","node_count":100,"edge_count":200}]}`,
	}
	resolver := NewResolver(mock)

	run, err := resolver.IngestStatus("run1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if run.ID != "run1" {
		t.Errorf("expected id 'run1', got %s", run.ID)
	}

	if run.Status != "COMPLETED" {
		t.Errorf("expected status 'COMPLETED', got %s", run.Status)
	}

	if len(run.Services) != 1 {
		t.Errorf("expected 1 service, got %d", len(run.Services))
	}
}

// Error sentinel values for testing
var ErrNotInitialized = &mockError{"graph not initialized"}

type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}
