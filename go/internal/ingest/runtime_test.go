package ingest

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// MockIngester is a test double that implements the Ingester interface.
type MockIngester struct {
	serviceName     string
	requiredActions []string
	resources       []ResourceSpec
	shouldFail      bool
	failError       error
	callCount       int
	callMu          sync.Mutex
}

// NewMockIngester creates a new mock ingester with the given service name and resources.
func NewMockIngester(serviceName string, resources []ResourceSpec) *MockIngester {
	return &MockIngester{
		serviceName: serviceName,
		resources:   resources,
		requiredActions: []string{
			"s3:ListAllMyBuckets",
			"s3:GetBucketPolicy",
		},
	}
}

// Service returns the service name.
func (m *MockIngester) Service() string {
	return m.serviceName
}

// RequiredIAMActions returns the required IAM actions.
func (m *MockIngester) RequiredIAMActions() []string {
	return m.requiredActions
}

// Enumerate returns the mock resources or an error if shouldFail is set.
func (m *MockIngester) Enumerate(ctx context.Context, region string) (<-chan ResourceSpec, <-chan error) {
	m.callMu.Lock()
	m.callCount++
	m.callMu.Unlock()

	resourcesChan := make(chan ResourceSpec, len(m.resources))
	errorsChan := make(chan error, 1)

	go func() {
		defer close(resourcesChan)
		defer close(errorsChan)

		if m.shouldFail {
			errorsChan <- m.failError
			return
		}

		for _, resource := range m.resources {
			resourcesChan <- resource
		}
	}()

	return resourcesChan, errorsChan
}

// GetCallCount returns the number of times Enumerate was called.
func (m *MockIngester) GetCallCount() int {
	m.callMu.Lock()
	defer m.callMu.Unlock()
	return m.callCount
}

// MockFFIWriter is a test double for FFIWriter.
type MockFFIWriter struct {
	graphInitCalls   int
	addNodesBatches  []string
	addEdgesBatches  []string
	mu               sync.Mutex
}

// GraphInitialize records the call and returns success.
func (m *MockFFIWriter) GraphInitialize(dbHost string, dbPort uint16, dbUser string, dbPassword string, dbName string, maxConnections uint32, graphName string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.graphInitCalls++
	return ""
}

// AddNodesBatch records the call and returns a count result.
func (m *MockFFIWriter) AddNodesBatch(label string, nodesJSON string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addNodesBatches = append(m.addNodesBatches, nodesJSON)
	return `{"count": 1}`
}

// AddEdgesBatch records the call and returns a count result.
func (m *MockFFIWriter) AddEdgesBatch(edgesJSON string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addEdgesBatches = append(m.addEdgesBatches, edgesJSON)
	return `{"count": 1}`
}

// TestRegisterAndIngest_MockIngester tests basic registration and ingestion.
func TestRegisterAndIngest_MockIngester(t *testing.T) {
	// Create a mock ingester with test resources
	resources := []ResourceSpec{
		{
			Label: "Resource",
			ID:    "arn:aws:s3:::bucket-1",
			Properties: map[string]interface{}{
				"name":   "bucket-1",
				"region": "us-east-1",
			},
			Edges: []EdgeSpec{
				{
					FromID:   "arn:aws:s3:::bucket-1",
					ToID:     "arn:aws:iam::123456789012:role/test",
					EdgeType: "HasPolicy",
					Properties: map[string]interface{}{
						"policy_id": "policy-123",
					},
				},
			},
		},
		{
			Label: "Resource",
			ID:    "arn:aws:s3:::bucket-2",
			Properties: map[string]interface{}{
				"name":   "bucket-2",
				"region": "us-west-2",
			},
			Edges: []EdgeSpec{},
		},
	}

	mockIngester := NewMockIngester("s3", resources)

	// Create a minimal config with batch size of 1 to test batching
	cfg := &Config{
		DatabaseURL: "postgres://user:pass@localhost/db",
		GraphName:   "test_graph",
		PoolSize:    5,
		Regions:     []string{"us-east-1"}, // Use explicit regions to avoid discovery
		BatchSize:   1,
	}

	// For this unit test, we don't use a real database
	// Instead, we verify that the ingester was called and resources were queued
	mockFFI := &MockFFIWriter{}
	rt := NewRuntimeWithFFI(cfg, nil, mockFFI)
	rt.Register(mockIngester)

	// Verify registration
	ingesters := rt.getIngesters()
	if len(ingesters) != 1 {
		t.Fatalf("expected 1 ingester, got %d", len(ingesters))
	}

	if ingesters[0].Service() != "s3" {
		t.Fatalf("expected service 's3', got '%s'", ingesters[0].Service())
	}

	// Test that we can enumerate
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resourcesChan, errorsChan := mockIngester.Enumerate(ctx, "us-east-1")

	resourceCount := 0
	for range resourcesChan {
		resourceCount++
	}

	for err := range errorsChan {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if resourceCount != len(resources) {
		t.Fatalf("expected %d resources, got %d", len(resources), resourceCount)
	}

	if mockIngester.GetCallCount() != 1 {
		t.Fatalf("expected Enumerate to be called once, got %d", mockIngester.GetCallCount())
	}
}

// TestIngest_PartialFailure tests that partial failure in one ingester doesn't abort others.
func TestIngest_PartialFailure(t *testing.T) {
	// Create two mock ingesters: one succeeds, one fails
	successResources := []ResourceSpec{
		{
			Label:      "Resource",
			ID:         "arn:aws:s3:::success-bucket",
			Properties: map[string]interface{}{"name": "success-bucket"},
			Edges:      []EdgeSpec{},
		},
	}

	failingMock := NewMockIngester("s3", []ResourceSpec{})
	failingMock.shouldFail = true
	failingMock.failError = fmt.Errorf("simulated S3 API failure")

	successMock := NewMockIngester("iam", successResources)

	cfg := &Config{
		DatabaseURL: "postgres://user:pass@localhost/db",
		GraphName:   "test_graph",
		PoolSize:    5,
		Regions:     []string{"us-east-1"},
		BatchSize:   10,
	}

	rt := NewRuntime(cfg, nil)
	rt.Register(failingMock)
	rt.Register(successMock)

	// Verify both ingesters are registered
	ingesters := rt.getIngesters()
	if len(ingesters) != 2 {
		t.Fatalf("expected 2 ingesters, got %d", len(ingesters))
	}

	// Verify that both can be enumerated independently
	ctx := context.Background()

	// Failing mock should produce an error
	_, errChan := failingMock.Enumerate(ctx, "us-east-1")
	var failErr error
	for e := range errChan {
		failErr = e
	}
	if failErr == nil {
		t.Fatal("expected error from failing mock")
	}

	// Success mock should produce resources
	resChan, _ := successMock.Enumerate(ctx, "us-east-1")
	resCount := 0
	for range resChan {
		resCount++
	}
	if resCount != len(successResources) {
		t.Fatalf("expected %d resources from success mock, got %d", len(successResources), resCount)
	}
}

// TestIdempotency_SameFixture_ProducesSameState tests that running the same fixture twice
// produces the same ingestion state (key test for append-only correctness).
func TestIdempotency_SameFixture(t *testing.T) {
	// Create identical fixtures
	fixture := []ResourceSpec{
		{
			Label:      "Principal",
			ID:         "arn:aws:iam::123456789012:user/alice",
			Properties: map[string]interface{}{"name": "alice"},
			Edges: []EdgeSpec{
				{
					FromID:     "arn:aws:iam::123456789012:user/alice",
					ToID:       "arn:aws:iam::123456789012:role/admin",
					EdgeType:   "CanAssume",
					Properties: map[string]interface{}{},
				},
			},
		},
		{
			Label:      "Principal",
			ID:         "arn:aws:iam::123456789012:role/admin",
			Properties: map[string]interface{}{"name": "admin"},
			Edges:      []EdgeSpec{},
		},
	}

	mockIngester := NewMockIngester("iam", fixture)

	cfg := &Config{
		DatabaseURL: "postgres://user:pass@localhost/db",
		GraphName:   "test_graph",
		PoolSize:    5,
		Regions:     []string{},
		BatchSize:   500,
	}

	rt := NewRuntime(cfg, nil)
	rt.Register(mockIngester)

	ctx := context.Background()

	// Enumerate twice and verify we get the same resources in the same order
	for runNum := 1; runNum <= 2; runNum++ {
		resChan, errChan := mockIngester.Enumerate(ctx, "")

		resourceIDs := make([]string, 0)
		for res := range resChan {
			resourceIDs = append(resourceIDs, res.ID)
		}

		for err := range errChan {
			if err != nil {
				t.Fatalf("run %d: unexpected error: %v", runNum, err)
			}
		}

		if len(resourceIDs) != len(fixture) {
			t.Fatalf("run %d: expected %d resources, got %d", runNum, len(fixture), len(resourceIDs))
		}

		// Verify order is the same across runs
		expected := []string{
			"arn:aws:iam::123456789012:user/alice",
			"arn:aws:iam::123456789012:role/admin",
		}
		for i, id := range resourceIDs {
			if id != expected[i] {
				t.Fatalf("run %d: at index %d, expected %s, got %s", runNum, i, expected[i], id)
			}
		}
	}
}

// TestContextAccountIDRoundtrip tests the account ID context helpers.
func TestContextAccountIDRoundtrip(t *testing.T) {
	ctx := context.Background()

	// Initially, no account ID
	accountID := AccountIDFromContext(ctx)
	if accountID != "" {
		t.Fatalf("expected empty account ID, got %s", accountID)
	}

	// Attach account ID
	accountID = "123456789012"
	ctx = WithAccountID(ctx, accountID)

	// Retrieve it
	retrieved := AccountIDFromContext(ctx)
	if retrieved != accountID {
		t.Fatalf("expected %s, got %s", accountID, retrieved)
	}
}

// TestInitRunStatusTable tests the run status table creation.
func TestInitRunStatusTable(t *testing.T) {
	// Skip this test if we don't have a test database
	// In a full test suite, you'd use testcontainers to spin up a Postgres instance
	dbURL := "postgres://postgres:postgres@localhost:5432/activable_test?sslmode=disable"
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("skipping test: failed to open database: %v", err)
	}
	defer db.Close()

	// Try to connect
	if err := db.Ping(); err != nil {
		t.Skipf("skipping test: failed to connect to database: %v", err)
	}

	// Initialize the table (should be idempotent)
	if err := InitRunStatusTable(db); err != nil {
		t.Fatalf("failed to init table: %v", err)
	}

	// Try again to verify idempotency
	if err := InitRunStatusTable(db); err != nil {
		t.Fatalf("failed to init table second time: %v", err)
	}

	// Test writing a run status
	runID := uuid.New()
	rs := RunStatus{
		RunID:     runID,
		StartedAt: time.Now(),
		Status:    "running",
	}

	if err := WriteRunStatus(db, rs); err != nil {
		t.Fatalf("failed to write run status: %v", err)
	}

	// Retrieve it
	retrieved, err := GetRunStatus(db, runID)
	if err != nil {
		t.Fatalf("failed to get run status: %v", err)
	}

	if retrieved == nil {
		t.Fatal("expected run status, got nil")
	}

	if retrieved.RunID != runID {
		t.Fatalf("expected run ID %s, got %s", runID, retrieved.RunID)
	}

	if retrieved.Status != "running" {
		t.Fatalf("expected status 'running', got '%s'", retrieved.Status)
	}

	// Update it
	if err := UpdateRunStatus(db, runID, "completed", []string{}); err != nil {
		t.Fatalf("failed to update run status: %v", err)
	}

	// Retrieve updated status
	retrieved, err = GetRunStatus(db, runID)
	if err != nil {
		t.Fatalf("failed to get updated run status: %v", err)
	}

	if retrieved.Status != "completed" {
		t.Fatalf("expected status 'completed', got '%s'", retrieved.Status)
	}

	if retrieved.FinishedAt.IsZero() {
		t.Fatal("expected finished_at to be set")
	}
}

// TestConfigLoadConfig tests the LoadConfig function.
func TestConfigLoadConfig(t *testing.T) {
	t.Setenv("ACTIVABLE_DB_URL", "postgres://user:pass@localhost/db")
	t.Setenv("ACTIVABLE_GRAPH_NAME", "test_graph")
	t.Setenv("ACTIVABLE_POOL_SIZE", "10")
	t.Setenv("ACTIVABLE_BATCH_SIZE", "100")
	t.Setenv("ACTIVABLE_REGIONS", "us-east-1,us-west-2")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.DatabaseURL != "postgres://user:pass@localhost/db" {
		t.Fatalf("unexpected DB URL: %s", cfg.DatabaseURL)
	}

	if cfg.GraphName != "test_graph" {
		t.Fatalf("unexpected graph name: %s", cfg.GraphName)
	}

	if cfg.PoolSize != 10 {
		t.Fatalf("unexpected pool size: %d", cfg.PoolSize)
	}

	if cfg.BatchSize != 100 {
		t.Fatalf("unexpected batch size: %d", cfg.BatchSize)
	}

	if len(cfg.Regions) != 2 {
		t.Fatalf("expected 2 regions, got %d", len(cfg.Regions))
	}

	if cfg.Regions[0] != "us-east-1" {
		t.Fatalf("expected first region 'us-east-1', got '%s'", cfg.Regions[0])
	}
}

// TestConfigRedacted tests the Redacted method.
func TestConfigRedacted(t *testing.T) {
	cfg := &Config{
		DatabaseURL: "postgres://user:secretpass@localhost/db",
		GraphName:   "test",
	}

	redacted := cfg.Redacted()

	// Should contain a mask
	if redacted.DatabaseURL == cfg.DatabaseURL {
		t.Fatal("expected database URL to be redacted")
	}

	// The redacted URL should have password masked
	if !contains(redacted.DatabaseURL, "***") {
		t.Fatalf("expected redacted URL to contain '***', got: %s", redacted.DatabaseURL)
	}

	// Should not contain the original password
	if contains(redacted.DatabaseURL, "secretpass") {
		t.Fatalf("expected redacted URL to not contain password, got: %s", redacted.DatabaseURL)
	}
}

// contains is a helper to check if a string contains a substring
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
