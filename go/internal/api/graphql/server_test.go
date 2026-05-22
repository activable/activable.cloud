package graphql

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestHealthCheckHandler(t *testing.T) {
	t.Run("health check returns 200 when healthy", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		mockFFI := &MockFFI{HealthCheckResult: "ok"}
		server := NewServerWithFFI(":8080", logger, mockFFI)

		req := httptest.NewRequest("GET", "/healthz", nil)
		w := httptest.NewRecorder()

		handler := server.healthCheckHandler()
		handler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}

		body, _ := io.ReadAll(w.Body)
		bodyStr := string(body)
		if !contains(bodyStr, "healthy") {
			t.Errorf("expected 'healthy' in response, got %s", bodyStr)
		}
	})

	t.Run("health check returns 503 when unhealthy", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		mockFFI := &MockFFI{HealthCheckResult: "connection refused"}
		server := NewServerWithFFI(":8080", logger, mockFFI)

		req := httptest.NewRequest("GET", "/healthz", nil)
		w := httptest.NewRecorder()

		handler := server.healthCheckHandler()
		handler(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("expected status 503, got %d", w.Code)
		}

		body, _ := io.ReadAll(w.Body)
		bodyStr := string(body)
		if !contains(bodyStr, "unhealthy") {
			t.Errorf("expected 'unhealthy' in response, got %s", bodyStr)
		}
	})
}

func TestPlaygroundHandler(t *testing.T) {
	t.Run("playground returns HTML", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		server := NewServer(":8080", logger)

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		handler := server.playgroundHandler()
		handler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}

		contentType := w.Header().Get("Content-Type")
		if contentType != "text/html; charset=utf-8" {
			t.Errorf("expected text/html content type, got %s", contentType)
		}

		body, _ := io.ReadAll(w.Body)
		bodyStr := string(body)
		if !contains(bodyStr, "GraphQL") {
			t.Errorf("expected 'GraphQL' in response HTML")
		}
	})
}

func TestGraphQLHandler(t *testing.T) {
	t.Run("graphql endpoint returns 405 for GET", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		mockFFI := &MockFFI{}
		server := NewServerWithFFI(":8080", logger, mockFFI)

		req := httptest.NewRequest("GET", "/graphql", nil)
		w := httptest.NewRecorder()

		handler := server.graphqlHandler(&Resolver{})
		handler(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected status 405, got %d", w.Code)
		}
	})
}

func TestServerCreation(t *testing.T) {
	t.Run("new server with FFI", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
		mockFFI := &MockFFI{}
		server := NewServerWithFFI(":8080", logger, mockFFI)

		if server == nil {
			t.Error("expected non-nil server")
		}
		if server.addr != ":8080" {
			t.Errorf("expected addr :8080, got %s", server.addr)
		}
		if server.ffi == nil {
			t.Error("expected non-nil FFI client")
		}
	})
}

// Helper function
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
