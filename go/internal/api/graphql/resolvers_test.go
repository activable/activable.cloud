package graphql

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
)

// MockFFI allows us to mock FFI responses without a real database.
type MockFFI struct {
	FindNodeResult    string
	WalkEdgesResult   string
	PathFinderResult  string
	BlastRadiusResult string
	SubgraphResult    string
	HealthCheckResult string
}

// Implement FFIClient interface
func (m *MockFFI) QueryFindNode(graphName string, label string, id string) string {
	return m.FindNodeResult
}

func (m *MockFFI) QueryWalkEdges(graphName string, startID string, edgeTypes []string, direction string, depth uint32) string {
	return m.WalkEdgesResult
}

func (m *MockFFI) QueryPathFinder(graphName string, startID string, endID string, edgeTypes []string, maxHops uint32) string {
	return m.PathFinderResult
}

func (m *MockFFI) QueryBlastRadius(graphName string, nodeID string, edgeTypes []string, maxHops uint32) string {
	return m.BlastRadiusResult
}

func (m *MockFFI) QuerySubgraph(graphName string, centerID string, radius uint32) string {
	return m.SubgraphResult
}

func (m *MockFFI) HealthCheck() string {
	return m.HealthCheckResult
}

func newTestResolver() *Resolver {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mockFFI := &MockFFI{
		FindNodeResult:    "null",
		WalkEdgesResult:   "[]",
		PathFinderResult:  "[]",
		BlastRadiusResult: "[]",
		SubgraphResult:    `{"nodes": [], "edges": []}`,
		HealthCheckResult: "ok",
	}
	return NewResolverWithFFI(logger, mockFFI, "default")
}

func TestResolverCreation(t *testing.T) {
	t.Run("new resolver with real FFI", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		resolver := NewResolver(logger)
		if resolver == nil {
			t.Error("expected non-nil resolver")
		}
		if resolver.logger == nil {
			t.Error("expected non-nil logger in resolver")
		}
		if resolver.ffi == nil {
			t.Error("expected non-nil FFI client")
		}
	})

	t.Run("new resolver with custom FFI", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		mockFFI := &MockFFI{}
		resolver := NewResolverWithFFI(logger, mockFFI, "test-graph")
		if resolver == nil {
			t.Error("expected non-nil resolver")
		}
		if resolver.graphName != "test-graph" {
			t.Errorf("expected graph name 'test-graph', got %s", resolver.graphName)
		}
	})
}

func TestFindNode(t *testing.T) {
	ctx := context.Background()

	// Test case 1: Node found
	t.Run("node found", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		mockFFI := &MockFFI{
			FindNodeResult: `{"id":"arn:aws:iam::123456789:role/test","label":"Principal","properties":"{}"}`,
		}
		resolver := NewResolverWithFFI(logger, mockFFI, "default")
		result, err := resolver.FindNode(ctx, "Principal", "arn:aws:iam::123456789:role/test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("expected non-nil result")
		}
		if result.ID != "arn:aws:iam::123456789:role/test" {
			t.Errorf("expected ID to match, got %s", result.ID)
		}
	})

	// Test case 2: Node not found
	t.Run("node not found", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		mockFFI := &MockFFI{FindNodeResult: "null"}
		resolver := NewResolverWithFFI(logger, mockFFI, "default")
		result, err := resolver.FindNode(ctx, "Principal", "arn:aws:iam::123456789:role/missing")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result != nil {
			t.Errorf("expected nil result, got %v", result)
		}
	})

	// Test case 3: Error in response
	t.Run("error response", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		mockFFI := &MockFFI{FindNodeResult: `{"error":"not found"}`}
		resolver := NewResolverWithFFI(logger, mockFFI, "default")
		_, err := resolver.FindNode(ctx, "Principal", "arn:aws:iam::123456789:role/missing")
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestWalkEdges(t *testing.T) {
	ctx := context.Background()

	// Test case 1: Valid direction - outgoing
	t.Run("valid direction outgoing", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		mockFFI := &MockFFI{WalkEdgesResult: `[{"id":"a","label":"Principal"}]`}
		resolver := NewResolverWithFFI(logger, mockFFI, "default")
		result, err := resolver.WalkEdges(ctx, "arn:aws:iam::123456789:role/test", []string{}, "outgoing", 2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("expected non-nil result")
		}
	})

	// Test case 2: Valid direction - incoming
	t.Run("valid direction incoming", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		mockFFI := &MockFFI{WalkEdgesResult: "[]"}
		resolver := NewResolverWithFFI(logger, mockFFI, "default")
		result, err := resolver.WalkEdges(ctx, "arn:aws:iam::123456789:role/test", []string{}, "incoming", 2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("expected non-nil result")
		}
	})

	// Test case 3: Valid direction - both
	t.Run("valid direction both", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		mockFFI := &MockFFI{WalkEdgesResult: "[]"}
		resolver := NewResolverWithFFI(logger, mockFFI, "default")
		result, err := resolver.WalkEdges(ctx, "arn:aws:iam::123456789:role/test", []string{}, "both", 2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("expected non-nil result")
		}
	})

	// Test case 4: Invalid direction
	t.Run("invalid direction", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		mockFFI := &MockFFI{}
		resolver := NewResolverWithFFI(logger, mockFFI, "default")
		_, err := resolver.WalkEdges(ctx, "arn:aws:iam::123456789:role/test", []string{}, "invalid", 2)
		if err == nil {
			t.Error("expected error for invalid direction")
		}
	})
}

func TestPathFinder(t *testing.T) {
	ctx := context.Background()

	t.Run("path found", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		mockFFI := &MockFFI{
			PathFinderResult: `[{"nodes":[{"id":"a","label":"Principal"},{"id":"b","label":"Resource"}],"length":1}]`,
		}
		resolver := NewResolverWithFFI(logger, mockFFI, "default")
		result, err := resolver.PathFinder(ctx, "arn:aws:iam::123456789:role/source", "arn:aws:iam::123456789:role/target", []string{}, 5)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("expected non-nil result")
		}
	})

	t.Run("no path found", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		mockFFI := &MockFFI{PathFinderResult: "[]"}
		resolver := NewResolverWithFFI(logger, mockFFI, "default")
		result, err := resolver.PathFinder(ctx, "arn:aws:iam::123456789:role/source", "arn:aws:iam::123456789:role/target", []string{}, 5)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("expected non-nil result")
		}
	})
}

func TestBlastRadius(t *testing.T) {
	ctx := context.Background()

	t.Run("blast radius computed", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		mockFFI := &MockFFI{
			BlastRadiusResult: `[{"id":"a","label":"Principal"},{"id":"b","label":"Resource"}]`,
		}
		resolver := NewResolverWithFFI(logger, mockFFI, "default")
		result, err := resolver.BlastRadius(ctx, "arn:aws:iam::123456789:role/test", []string{}, 3)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("expected non-nil result")
		}
	})

	t.Run("blast radius empty", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		mockFFI := &MockFFI{BlastRadiusResult: "[]"}
		resolver := NewResolverWithFFI(logger, mockFFI, "default")
		result, err := resolver.BlastRadius(ctx, "arn:aws:iam::123456789:role/test", []string{}, 3)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("expected non-nil result")
		}
	})
}

func TestSubgraph(t *testing.T) {
	ctx := context.Background()

	t.Run("subgraph fetched", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		mockFFI := &MockFFI{
			SubgraphResult: `{"nodes":[{"id":"a","label":"Principal"}],"edges":[{"fromId":"a","toId":"b","edgeType":"ASSUME"}]}`,
		}
		resolver := NewResolverWithFFI(logger, mockFFI, "default")
		result, err := resolver.Subgraph(ctx, "arn:aws:iam::123456789:role/test", 2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("expected non-nil result")
		}
	})

	t.Run("subgraph empty", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		mockFFI := &MockFFI{SubgraphResult: `{"nodes":[],"edges":[]}`}
		resolver := NewResolverWithFFI(logger, mockFFI, "default")
		result, err := resolver.Subgraph(ctx, "arn:aws:iam::123456789:role/test", 2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("expected non-nil result")
		}
	})
}

func TestIngestStatus(t *testing.T) {
	ctx := context.Background()
	resolver := newTestResolver()

	t.Run("ingest status retrieved", func(t *testing.T) {
		runID := "test-run-123"
		result, err := resolver.IngestStatus(ctx, runID)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("expected non-nil result")
		}
		if result.ID != runID {
			t.Errorf("expected ID %s, got %s", runID, result.ID)
		}
		if result.Status != "RUNNING" {
			t.Errorf("expected status RUNNING, got %s", result.Status)
		}
	})
}

func TestTriggerIngest(t *testing.T) {
	ctx := context.Background()
	resolver := newTestResolver()

	t.Run("ingest triggered with AWS", func(t *testing.T) {
		result, err := resolver.TriggerIngest(ctx, "AWS", []string{"us-east-1", "us-west-2"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.Status != "RUNNING" {
			t.Errorf("expected status RUNNING, got %s", result.Status)
		}
		if len(result.Services) == 0 {
			t.Error("expected non-empty services list")
		}
		if result.Services[0].Name != "AWS" {
			t.Errorf("expected service name AWS, got %s", result.Services[0].Name)
		}
	})

	t.Run("ingest with unsupported provider", func(t *testing.T) {
		_, err := resolver.TriggerIngest(ctx, "GCP", []string{"us-central1"})
		if err == nil {
			t.Error("expected error for unsupported provider")
		}
	})

	t.Run("ingest with empty regions", func(t *testing.T) {
		_, err := resolver.TriggerIngest(ctx, "AWS", []string{})
		if err == nil {
			t.Error("expected error for empty regions")
		}
	})
}

// JSON serialization tests (branch coverage for model types)
func TestNodeSerialization(t *testing.T) {
	t.Run("node marshals to JSON", func(t *testing.T) {
		node := &Node{
			ID:         "arn:aws:iam::123456789:role/test",
			Label:      "Principal",
			Properties: `{"name": "test"}`,
		}
		data, err := json.Marshal(node)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) == "" {
			t.Error("expected non-empty JSON")
		}
	})

	t.Run("node unmarshals from JSON", func(t *testing.T) {
		data := []byte(`{"id":"arn:aws:iam::123456789:role/test","label":"Principal","properties":"{}"}`)
		var node Node
		err := json.Unmarshal(data, &node)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if node.ID != "arn:aws:iam::123456789:role/test" {
			t.Errorf("expected ID to be set, got %s", node.ID)
		}
	})
}

func TestPathSerialization(t *testing.T) {
	t.Run("path marshals to JSON", func(t *testing.T) {
		path := &Path{
			Nodes: []*NodeRef{
				{ID: "a", Label: "Principal"},
				{ID: "b", Label: "Resource"},
			},
			Length: 1,
		}
		data, err := json.Marshal(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) == "" {
			t.Error("expected non-empty JSON")
		}
	})
}

func TestSubgraphSerialization(t *testing.T) {
	t.Run("subgraph marshals to JSON", func(t *testing.T) {
		subgraph := &Subgraph{
			Nodes: []*NodeRef{
				{ID: "a", Label: "Principal"},
			},
			Edges: []*Edge{
				{FromID: "a", ToID: "b", EdgeType: "ASSUME"},
			},
		}
		data, err := json.Marshal(subgraph)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) == "" {
			t.Error("expected non-empty JSON")
		}
	})
}

func TestIngestRunSerialization(t *testing.T) {
	t.Run("ingest run marshals to JSON", func(t *testing.T) {
		run := &IngestRun{
			ID:        "test-run",
			Status:    "RUNNING",
			StartedAt: "2026-05-22T10:00:00Z",
			Services: []*ServiceStatus{
				{
					Name:      "AWS",
					Status:    "RUNNING",
					NodeCount: 100,
					EdgeCount: 250,
					Error:     nil,
				},
			},
		}
		data, err := json.Marshal(run)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) == "" {
			t.Error("expected non-empty JSON")
		}
	})

	t.Run("ingest run with error marshals to JSON", func(t *testing.T) {
		errMsg := "connection failed"
		run := &IngestRun{
			ID:        "test-run",
			Status:    "FAILED",
			StartedAt: "2026-05-22T10:00:00Z",
			Services: []*ServiceStatus{
				{
					Name:      "AWS",
					Status:    "FAILED",
					NodeCount: 0,
					EdgeCount: 0,
					Error:     &errMsg,
				},
			},
		}
		data, err := json.Marshal(run)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) == "" {
			t.Error("expected non-empty JSON")
		}
	})
}

func TestNodeRefSerialization(t *testing.T) {
	t.Run("node ref marshals to JSON", func(t *testing.T) {
		ref := &NodeRef{
			ID:    "arn:aws:iam::123456789:role/test",
			Label: "Principal",
		}
		data, err := json.Marshal(ref)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) == "" {
			t.Error("expected non-empty JSON")
		}
	})
}

func TestEdgeSerialization(t *testing.T) {
	t.Run("edge marshals to JSON", func(t *testing.T) {
		edge := &Edge{
			FromID:   "a",
			ToID:     "b",
			EdgeType: "ASSUME",
		}
		data, err := json.Marshal(edge)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) == "" {
			t.Error("expected non-empty JSON")
		}
	})
}

func TestServiceStatusSerialization(t *testing.T) {
	t.Run("service status marshals to JSON", func(t *testing.T) {
		status := &ServiceStatus{
			Name:      "AWS",
			Status:    "RUNNING",
			NodeCount: 100,
			EdgeCount: 250,
			Error:     nil,
		}
		data, err := json.Marshal(status)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) == "" {
			t.Error("expected non-empty JSON")
		}
	})
}
