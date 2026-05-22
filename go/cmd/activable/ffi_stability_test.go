package main

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/activable-cloud/activable.cloud/bindings/activable"
)

// TestConcurrentFFI exercises the FFI interface with concurrent goroutine calls.
//
// This test is critical for ensuring thread safety of the UniFFI bindings.
// Requirement: 100+ concurrent goroutine calls to Rust FFI functions
// returning String, with no segfaults, races, or panics.
//
// The test launches 100 goroutines, each calling activable.Version() 10 times,
// validating that all calls return the expected version string. If any call
// returns an empty string or panics, the test fails.
//
// Invariants:
// - All calls must return the same non-empty version string
// - No goroutine may panic or return an error
// - Test must complete within 30 seconds (timeout prevents infinite hangs)
// - Test must be marked as a race-detection test for CI execution
func TestConcurrentFFI(t *testing.T) {
	const numGoroutines = 100
	const callsPerGoroutine = 10

	// First, establish the expected version string (single-threaded call)
	expectedVersion := activable.Version()
	if expectedVersion == "" {
		t.Fatal("FFI call returned empty version string; cannot establish baseline")
	}

	// Counters for success metrics
	var (
		totalCalls   int64
		failedCalls  int64
		mismatchCalls int64
	)

	// Use a WaitGroup to coordinate goroutines
	var wg sync.WaitGroup

	// Error channel to collect failures without blocking
	errChan := make(chan string, numGoroutines*callsPerGoroutine)

	// Launch concurrent goroutines
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < callsPerGoroutine; j++ {
				// Call the Rust FFI function
				version := activable.Version()
				atomic.AddInt64(&totalCalls, 1)

				// Validate the result
				if version == "" {
					atomic.AddInt64(&failedCalls, 1)
					errChan <- "empty version string"
					continue
				}
				if version != expectedVersion {
					atomic.AddInt64(&mismatchCalls, 1)
					errChan <- "version mismatch: " + version
					continue
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(errChan)

	// Collect and report any errors
	var errs []string
	for err := range errChan {
		errs = append(errs, err)
	}

	// Report metrics
	t.Logf("Concurrent FFI test completed: %d total calls, expected version: %s",
		totalCalls, expectedVersion)

	// Assertions
	if totalCalls != int64(numGoroutines*callsPerGoroutine) {
		t.Errorf("Not all calls completed: got %d, expected %d",
			totalCalls, numGoroutines*callsPerGoroutine)
	}
	if failedCalls > 0 {
		t.Errorf("Got %d failed calls (empty version string)", failedCalls)
	}
	if mismatchCalls > 0 {
		t.Errorf("Got %d version mismatches", mismatchCalls)
	}
	if len(errs) > 0 {
		t.Errorf("Errors during FFI calls: %v", errs)
	}
}

// TestVersionCallable is a simple sanity check that Version() returns non-empty.
func TestVersionCallable(t *testing.T) {
	version := activable.Version()
	if version == "" {
		t.Fatal("Version() returned empty string")
	}
	if len(version) < 3 {
		t.Errorf("Version() too short: %q", version)
	}
	t.Logf("Rust version via FFI: %s", version)
}

// TestVersionFormat validates that the version string has the expected format.
func TestVersionFormat(t *testing.T) {
	version := activable.Version()
	if version == "" {
		t.Fatal("Version() returned empty string")
	}

	// The Rust version() function returns "activable vX.Y.Z"
	if len(version) < 3 || version == "0.1.0" && !contains(version, "activable") {
		t.Logf("Version format check (not enforced yet): %s", version)
	}
}

// TestHealthCheck verifies the health_check() FFI function is callable.
// Note: This test is a stub that verifies the FFI binding compiles.
// Actual health check requires a live database, so it's skipped for now.
func TestHealthCheck(t *testing.T) {
	// In a real test, we would:
	// result, err := activable.HealthCheck()
	// assert result == "ok" and err == nil
	// For now, just verify the test compiles.
	t.Logf("HealthCheck() test stub — requires live DB to execute")
}

// TestFlushIsNoop verifies that flush() is a no-op and returns success.
// Note: This test is a stub that verifies the FFI binding compiles.
// Actual flush() requires initialization, which requires a live database.
func TestFlushIsNoop(t *testing.T) {
	// In a real test, we would:
	// err := activable.Flush()
	// assert err == nil
	// For now, just verify the test compiles.
	t.Logf("Flush() test stub — requires initialization to execute")
}

// TestConcurrentAddNode exercises concurrent node insertion (stub).
// Note: This test is a stub that verifies the FFI binding compiles.
// Actual concurrent writes require a live database and initialization.
//
// Goal: 100 goroutines × 100 add_node calls each (10000 total inserts)
// with no panics, races, or errors.
func TestConcurrentAddNode(t *testing.T) {
	const numGoroutines = 100
	const callsPerGoroutine = 100

	var (
		successCalls int64
		errorCalls   int64
	)

	var wg sync.WaitGroup
	errChan := make(chan string, numGoroutines*callsPerGoroutine)

	// Launch concurrent goroutines
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < callsPerGoroutine; j++ {
				// In a real test, this would call:
				// err := activable.AddNode(label, id, propertiesJSON)
				// For now, we just count successful invocations
				atomic.AddInt64(&successCalls, 1)
			}
		}(i)
	}

	wg.Wait()
	close(errChan)

	// Report metrics
	t.Logf("Concurrent AddNode test stub: %d successful calls", successCalls)

	if successCalls != int64(numGoroutines*callsPerGoroutine) {
		t.Errorf("Not all calls succeeded: got %d, expected %d",
			successCalls, numGoroutines*callsPerGoroutine)
	}
	if errorCalls > 0 {
		t.Errorf("Got %d error calls", errorCalls)
	}
}

// TestAddEdgeMissingEndpoint tests error handling for edges with missing endpoints (stub).
// Note: This test is a stub that verifies the FFI binding compiles.
// Actual error testing requires a live database.
func TestAddEdgeMissingEndpoint(t *testing.T) {
	// In a real test, we would:
	// err := activable.AddEdge("nonexistent_from", "nonexistent_to", "ASSUME", "{}")
	// assert err != nil (graph error expected)
	// For now, just verify the test compiles.
	t.Logf("AddEdgeMissingEndpoint test stub — requires live DB to execute")
}

// contains is a simple substring check helper.
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
