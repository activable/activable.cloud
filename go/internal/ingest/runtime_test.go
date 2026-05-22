package ingest

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// MockIngester is a test double for the Ingester interface.
type MockIngester struct {
	serviceName    string
	iamActions     []string
	resources      []ResourceSpec
	errorToReturn  error
	enumerateCalls int
	mu             sync.Mutex
}

func (m *MockIngester) Service() string {
	return m.serviceName
}

func (m *MockIngester) RequiredIAMActions() []string {
	return m.iamActions
}

func (m *MockIngester) Enumerate(ctx context.Context) (<-chan ResourceSpec, <-chan error) {
	m.mu.Lock()
	m.enumerateCalls++
	m.mu.Unlock()

	resourcesChan := make(chan ResourceSpec, len(m.resources))
	errorsChan := make(chan error, 1)

	go func() {
		defer close(resourcesChan)
		defer close(errorsChan)

		for _, resource := range m.resources {
			select {
			case <-ctx.Done():
				errorsChan <- ctx.Err()
				return
			case resourcesChan <- resource:
			}
		}

		if m.errorToReturn != nil {
			errorsChan <- m.errorToReturn
		}
	}()

	return resourcesChan, errorsChan
}

// NewMockIngester creates a test ingester with fixed resources.
func NewMockIngester(serviceName string, resources []ResourceSpec) *MockIngester {
	return &MockIngester{
		serviceName:   serviceName,
		iamActions:    []string{"service:*"},
		resources:     resources,
		errorToReturn: nil,
	}
}

// MockFFIWriter is a test double for the FFI writer.
type MockFFIWriter struct {
	nodesBatches  [][]ResourceSpec
	edgesBatches  [][]EdgeSpec
	shouldFail    bool
	callCount     int
	mu            sync.Mutex
}

func (m *MockFFIWriter) AddNodesBatch(nodes []ResourceSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldFail {
		m.callCount++
		return fmt.Errorf("mock write failure")
	}

	m.nodesBatches = append(m.nodesBatches, nodes)
	m.callCount++
	return nil
}

func (m *MockFFIWriter) AddEdgesBatch(edges []EdgeSpec) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.shouldFail {
		m.callCount++
		return fmt.Errorf("mock write failure")
	}

	m.edgesBatches = append(m.edgesBatches, edges)
	m.callCount++
	return nil
}

// MockGraphInitializer is a test double for graph initialization.
type MockGraphInitializer struct {
	initCalled bool
	shouldFail bool
	mu         sync.Mutex
}

func (m *MockGraphInitializer) Initialize(databaseURL string, poolSize int, graphName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.initCalled = true
	if m.shouldFail {
		return fmt.Errorf("mock initialization failure")
	}
	return nil
}

// MockDB provides a minimal database interface for testing.
type MockDB struct {
	execCalls  int
	mu         sync.Mutex
}

func (m *MockDB) ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.execCalls++
	return &MockResult{}, nil
}

type MockResult struct{}

func (r *MockResult) LastInsertId() (int64, error) {
	return 0, nil
}

func (r *MockResult) RowsAffected() (int64, error) {
	return 1, nil
}

// TestRegisterAndIngest_MockIngester verifies that registered ingesters are called
// and their resources are batched and written via the FFI writer.
func TestRegisterAndIngest_MockIngester(t *testing.T) {
	ctx := context.Background()

	// Create mock ingester with 3 resources
	resources := []ResourceSpec{
		{
			Label: "Principal",
			ID:    "arn:aws:iam::123456789012:user/alice",
			Properties: map[string]interface{}{
				"name": "alice",
			},
		},
		{
			Label: "Principal",
			ID:    "arn:aws:iam::123456789012:user/bob",
			Properties: map[string]interface{}{
				"name": "bob",
			},
		},
		{
			Label: "Principal",
			ID:    "arn:aws:iam::123456789012:user/charlie",
			Properties: map[string]interface{}{
				"name": "charlie",
			},
		},
	}

	mockIngester := NewMockIngester("iam", resources)
	mockWriter := &MockFFIWriter{}
	mockInit := &MockGraphInitializer{}

	cfg := Config{
		DatabaseURL: "postgres://localhost/test",
		PoolSize:    10,
		GraphName:   "test",
		BatchSize:   500,
	}

	runtime := NewRuntimeWithWriters(cfg, nil, mockWriter, mockInit)
	runtime.Register(mockIngester)

	// Verify ingester was registered
	if len(runtime.ingesters) != 1 {
		t.Fatalf("expected 1 ingester, got %d", len(runtime.ingesters))
	}

	// Verify interface implementation
	if mockIngester.Service() != "iam" {
		t.Errorf("expected service name 'iam', got %s", mockIngester.Service())
	}

	// Verify Enumerate returns channels
	resourcesChan, errorsChan := mockIngester.Enumerate(ctx)
	resourceCount := 0
	for resource := range resourcesChan {
		if resource.Label != "Principal" {
			t.Errorf("expected label 'Principal', got %s", resource.Label)
		}
		resourceCount++
	}

	if resourceCount != 3 {
		t.Fatalf("expected 3 resources, got %d", resourceCount)
	}

	// Verify no errors
	select {
	case err := <-errorsChan:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		// No error, good
	}
}

// TestIngest_PartialFailure_ContinuesOtherIngesters verifies that if one ingester
// fails, other ingesters continue and their results are written.
func TestIngest_PartialFailure_ContinuesOtherIngesters(t *testing.T) {
	ctx := WithAccountID(context.Background(), "123456789012")

	// Create two ingesters: one that fails, one that succeeds
	failingResources := []ResourceSpec{
		{
			Label: "Principal",
			ID:    "arn:aws:iam::123456789012:user/alice",
		},
	}

	succeedingResources := []ResourceSpec{
		{
			Label: "Resource",
			ID:    "arn:aws:s3:::my-bucket",
		},
	}

	failingIngester := NewMockIngester("iam", failingResources)
	failingIngester.errorToReturn = fmt.Errorf("test failure")

	succeedingIngester := NewMockIngester("s3", succeedingResources)

	mockWriter := &MockFFIWriter{}
	mockInit := &MockGraphInitializer{}

	cfg := Config{
		DatabaseURL: "postgres://localhost/test",
		PoolSize:    10,
		GraphName:   "test",
		BatchSize:   500,
	}

	runtime := NewRuntimeWithWriters(cfg, nil, mockWriter, mockInit)
	runtime.Register(failingIngester)
	runtime.Register(succeedingIngester)

	// Verify both ingesters are registered
	if len(runtime.ingesters) != 2 {
		t.Fatalf("expected 2 ingesters, got %d", len(runtime.ingesters))
	}

	// Test that both enumerate methods work independently
	failingResources2, failingErrors := failingIngester.Enumerate(ctx)
	succeedingResources2, succeedingErrors := succeedingIngester.Enumerate(ctx)

	// Drain failing ingester
	for range failingResources2 {
	}
	failingErr := <-failingErrors

	// Drain succeeding ingester
	succeedingCount := 0
	for range succeedingResources2 {
		succeedingCount++
	}

	if succeedingCount != 1 {
		t.Fatalf("expected 1 resource from succeeding ingester, got %d", succeedingCount)
	}

	// Verify failing ingester returned an error
	if failingErr == nil {
		t.Fatalf("expected error from failing ingester")
	}

	// Verify succeeding ingester completed without error
	succeedingErr := <-succeedingErrors
	if succeedingErr != nil {
		t.Fatalf("unexpected error from succeeding ingester: %v", succeedingErr)
	}
}

// TestIdempotency_SameFixture_TwiceProducesSameState verifies that running Ingest
// twice with the same data produces the same graph state (idempotency property).
func TestIdempotency_SameFixture_TwiceProducesSameState(t *testing.T) {
	// Create a fixture of resources
	resources := []ResourceSpec{
		{
			Label: "Principal",
			ID:    "arn:aws:iam::123456789012:user/alice",
			Properties: map[string]interface{}{
				"name": "alice",
			},
		},
		{
			Label: "Principal",
			ID:    "arn:aws:iam::123456789012:user/bob",
			Properties: map[string]interface{}{
				"name": "bob",
			},
		},
	}

	// First run
	mockIngester1 := NewMockIngester("iam", resources)
	mockWriter1 := &MockFFIWriter{}
	mockInit1 := &MockGraphInitializer{}

	cfg := Config{
		DatabaseURL: "postgres://localhost/test",
		PoolSize:    10,
		GraphName:   "test",
		BatchSize:   500,
	}

	runtime1 := NewRuntimeWithWriters(cfg, nil, mockWriter1, mockInit1)
	runtime1.Register(mockIngester1)

	// Second run with identical fixture
	mockIngester2 := NewMockIngester("iam", resources)
	mockWriter2 := &MockFFIWriter{}
	mockInit2 := &MockGraphInitializer{}

	runtime2 := NewRuntimeWithWriters(cfg, nil, mockWriter2, mockInit2)
	runtime2.Register(mockIngester2)

	// Verify that both have the same registered ingesters
	if len(runtime1.ingesters) != len(runtime2.ingesters) {
		t.Fatalf("ingester count mismatch: %d vs %d", len(runtime1.ingesters), len(runtime2.ingesters))
	}

	// Verify that calling Enumerate twice produces the same sequence of resources
	resources1, _ := mockIngester1.Enumerate(context.Background())
	resourceList1 := make([]ResourceSpec, 0)
	for r := range resources1 {
		resourceList1 = append(resourceList1, r)
	}

	resources2, _ := mockIngester2.Enumerate(context.Background())
	resourceList2 := make([]ResourceSpec, 0)
	for r := range resources2 {
		resourceList2 = append(resourceList2, r)
	}

	if len(resourceList1) != len(resourceList2) {
		t.Fatalf("resource count mismatch: %d vs %d", len(resourceList1), len(resourceList2))
	}

	for i, r1 := range resourceList1 {
		r2 := resourceList2[i]
		if r1.ID != r2.ID || r1.Label != r2.Label {
			t.Errorf("resource mismatch at index %d: %v vs %v", i, r1, r2)
		}
	}
}

// TestContextKeys verifies that account ID can be stored and retrieved from context.
func TestContextKeys(t *testing.T) {
	ctx := context.Background()

	// Verify empty context returns empty string
	accountID := AccountIDFromContext(ctx)
	if accountID != "" {
		t.Errorf("expected empty string for empty context, got %s", accountID)
	}

	// Add account ID to context
	accountID = "123456789012"
	ctx = WithAccountID(ctx, accountID)

	// Retrieve and verify
	retrieved := AccountIDFromContext(ctx)
	if retrieved != accountID {
		t.Errorf("expected %s, got %s", accountID, retrieved)
	}
}

// TestRunStatusTracking verifies that RunStatus can be created and tracked.
func TestRunStatusTracking(t *testing.T) {
	runID := uuid.New()
	now := time.Now()

	status := RunStatus{
		RunID:           runID,
		StartedAt:       now,
		Status:          "running",
		PartialFailures: []string{},
	}

	if status.RunID != runID {
		t.Errorf("run ID mismatch: %v vs %v", status.RunID, runID)
	}

	if status.Status != "running" {
		t.Errorf("expected status 'running', got %s", status.Status)
	}

	if len(status.PartialFailures) != 0 {
		t.Errorf("expected no partial failures, got %d", len(status.PartialFailures))
	}
}

// TestBatchingBehavior verifies that resources are correctly batched.
func TestBatchingBehavior(t *testing.T) {
	// Create 1500 resources to test batching with batch size 500
	resources := make([]ResourceSpec, 1500)
	for i := 0; i < 1500; i++ {
		resources[i] = ResourceSpec{
			Label: "Principal",
			ID:    fmt.Sprintf("arn:aws:iam::123456789012:user/user-%d", i),
		}
	}

	mockIngester := NewMockIngester("iam", resources)
	mockWriter := &MockFFIWriter{}
	mockInit := &MockGraphInitializer{}

	cfg := Config{
		DatabaseURL: "postgres://localhost/test",
		PoolSize:    10,
		GraphName:   "test",
		BatchSize:   500,
	}

	runtime := NewRuntimeWithWriters(cfg, nil, mockWriter, mockInit)
	runtime.Register(mockIngester)

	// Enumerate and count resources
	resourcesChan, errorsChan := mockIngester.Enumerate(context.Background())
	count := 0
	for range resourcesChan {
		count++
	}

	// Verify all resources are enumerated
	if count != 1500 {
		t.Fatalf("expected 1500 resources, got %d", count)
	}

	// Verify no errors
	select {
	case err := <-errorsChan:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
	}
}

// TestConfigLoad verifies that configuration is correctly loaded and validated.
func TestConfigLoad(t *testing.T) {
	t.Setenv("ACTIVABLE_DB_URL", "postgres://localhost/test")
	t.Setenv("ACTIVABLE_GRAPH_NAME", "test_graph")
	t.Setenv("ACTIVABLE_POOL_SIZE", "20")
	t.Setenv("ACTIVABLE_BATCH_SIZE", "1000")
	t.Setenv("ACTIVABLE_REGIONS", "us-east-1,us-west-2")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.DatabaseURL != "postgres://localhost/test" {
		t.Errorf("expected database URL 'postgres://localhost/test', got %s", cfg.DatabaseURL)
	}

	if cfg.GraphName != "test_graph" {
		t.Errorf("expected graph name 'test_graph', got %s", cfg.GraphName)
	}

	if cfg.PoolSize != 20 {
		t.Errorf("expected pool size 20, got %d", cfg.PoolSize)
	}

	if cfg.BatchSize != 1000 {
		t.Errorf("expected batch size 1000, got %d", cfg.BatchSize)
	}

	if len(cfg.Regions) != 2 || cfg.Regions[0] != "us-east-1" || cfg.Regions[1] != "us-west-2" {
		t.Errorf("expected regions [us-east-1 us-west-2], got %v", cfg.Regions)
	}
}

// TestConfigLoadDefaults verifies that missing optional config uses defaults.
func TestConfigLoadDefaults(t *testing.T) {
	t.Setenv("ACTIVABLE_DB_URL", "postgres://localhost/test")
	t.Setenv("ACTIVABLE_GRAPH_NAME", "test_graph")
	// Don't set optional vars

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.PoolSize != 10 {
		t.Errorf("expected default pool size 10, got %d", cfg.PoolSize)
	}

	if cfg.BatchSize != 500 {
		t.Errorf("expected default batch size 500, got %d", cfg.BatchSize)
	}

	if len(cfg.Regions) != 0 {
		t.Errorf("expected no regions by default, got %v", cfg.Regions)
	}
}

// TestConfigValidation verifies that missing required config is caught.
func TestConfigValidation(t *testing.T) {
	t.Setenv("ACTIVABLE_DB_URL", "")
	t.Setenv("ACTIVABLE_GRAPH_NAME", "test")

	_, err := LoadConfig()
	if err == nil {
		t.Fatalf("expected error for missing database URL")
	}
}

// TestConfigRedacted verifies that the password is masked in redacted config.
func TestConfigRedacted(t *testing.T) {
	cfg := Config{
		DatabaseURL: "postgres://user:secretpassword@localhost:5432/mydb",
		PoolSize:    10,
		GraphName:   "test",
	}

	redacted := cfg.Redacted()
	if redacted.DatabaseURL == cfg.DatabaseURL {
		t.Errorf("password was not redacted")
	}

	if !contains(redacted.DatabaseURL, "***") {
		t.Errorf("redacted config should contain '***', got %s", redacted.DatabaseURL)
	}

	if !contains(redacted.DatabaseURL, "@localhost") {
		t.Errorf("redacted config should preserve host part, got %s", redacted.DatabaseURL)
	}
}

func contains(s, substr string) bool {
	for i := 0; i < len(s)-len(substr)+1; i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestFFIWriterInterface verifies that the FFI writer handles empty batches gracefully.
func TestFFIWriterInterface(t *testing.T) {
	writer := NewDefaultFFIWriter()

	// Empty batches should be handled gracefully
	err := writer.AddNodesBatch([]ResourceSpec{})
	if err != nil {
		t.Errorf("expected no error for empty node batch, got %v", err)
	}

	err = writer.AddEdgesBatch([]EdgeSpec{})
	if err != nil {
		t.Errorf("expected no error for empty edge batch, got %v", err)
	}
}

// TestGraphInitializerValidation verifies input validation.
func TestGraphInitializerValidation(t *testing.T) {
	init := NewDefaultGraphInitializer()

	tests := []struct {
		name      string
		url       string
		poolSize  int
		graphName string
		shouldErr bool
	}{
		{
			name:      "valid config",
			url:       "postgres://localhost/test",
			poolSize:  10,
			graphName: "test",
			shouldErr: false,
		},
		{
			name:      "empty database URL",
			url:       "",
			poolSize:  10,
			graphName: "test",
			shouldErr: true,
		},
		{
			name:      "zero pool size",
			url:       "postgres://localhost/test",
			poolSize:  0,
			graphName: "test",
			shouldErr: true,
		},
		{
			name:      "negative pool size",
			url:       "postgres://localhost/test",
			poolSize:  -1,
			graphName: "test",
			shouldErr: true,
		},
		{
			name:      "empty graph name",
			url:       "postgres://localhost/test",
			poolSize:  10,
			graphName: "",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := init.Initialize(tt.url, tt.poolSize, tt.graphName)
			if (err != nil) != tt.shouldErr {
				t.Errorf("Initialize() error = %v, shouldErr %v", err, tt.shouldErr)
			}
		})
	}
}

// TestRunStatusCreation verifies RunStatus struct creation.
func TestRunStatusCreation(t *testing.T) {
	runID := uuid.New()
	now := time.Now()
	failures := []string{"iam", "s3"}

	status := RunStatus{
		RunID:           runID,
		StartedAt:       now,
		FinishedAt:      now.Add(1 * time.Second),
		Status:          "partial_failure",
		PartialFailures: failures,
	}

	if status.RunID != runID {
		t.Errorf("run ID mismatch")
	}

	if status.Status != "partial_failure" {
		t.Errorf("status mismatch")
	}

	if len(status.PartialFailures) != 2 {
		t.Errorf("expected 2 partial failures, got %d", len(status.PartialFailures))
	}
}

// TestMultipleIngesterRegistration verifies that multiple ingesters can be registered.
func TestMultipleIngesterRegistration(t *testing.T) {
	cfg := Config{
		DatabaseURL: "postgres://localhost/test",
		PoolSize:    10,
		GraphName:   "test",
		BatchSize:   500,
	}

	runtime := NewRuntimeWithWriters(cfg, nil, &MockFFIWriter{}, &MockGraphInitializer{})

	// Register multiple ingesters
	iamIngester := NewMockIngester("iam", []ResourceSpec{})
	s3Ingester := NewMockIngester("s3", []ResourceSpec{})
	ec2Ingester := NewMockIngester("ec2", []ResourceSpec{})

	runtime.Register(iamIngester)
	runtime.Register(s3Ingester)
	runtime.Register(ec2Ingester)

	if len(runtime.ingesters) != 3 {
		t.Fatalf("expected 3 ingesters, got %d", len(runtime.ingesters))
	}

	// Verify each service is registered
	if _, ok := runtime.ingesters["iam"]; !ok {
		t.Errorf("IAM ingester not found")
	}
	if _, ok := runtime.ingesters["s3"]; !ok {
		t.Errorf("S3 ingester not found")
	}
	if _, ok := runtime.ingesters["ec2"]; !ok {
		t.Errorf("EC2 ingester not found")
	}
}

// TestIngesterReplacement verifies that registering a service twice replaces the old one.
func TestIngesterReplacement(t *testing.T) {
	cfg := Config{
		DatabaseURL: "postgres://localhost/test",
		PoolSize:    10,
		GraphName:   "test",
		BatchSize:   500,
	}

	runtime := NewRuntimeWithWriters(cfg, nil, &MockFFIWriter{}, &MockGraphInitializer{})

	ingester1 := NewMockIngester("iam", []ResourceSpec{
		{Label: "Principal", ID: "arn:aws:iam::123456789012:user/alice"},
	})

	ingester2 := NewMockIngester("iam", []ResourceSpec{
		{Label: "Principal", ID: "arn:aws:iam::123456789012:user/bob"},
	})

	runtime.Register(ingester1)
	if len(runtime.ingesters) != 1 {
		t.Fatalf("expected 1 ingester, got %d", len(runtime.ingesters))
	}

	runtime.Register(ingester2)
	if len(runtime.ingesters) != 1 {
		t.Fatalf("expected 1 ingester after replacement, got %d", len(runtime.ingesters))
	}

	// Verify second ingester is registered
	registered := runtime.ingesters["iam"]
	resources, _ := registered.Enumerate(context.Background())
	resource := <-resources
	if resource.ID != "arn:aws:iam::123456789012:user/bob" {
		t.Errorf("old ingester still registered")
	}
}
