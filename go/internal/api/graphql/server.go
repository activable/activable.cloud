package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// Server provides the GraphQL HTTP server.
type Server struct {
	resolver *Resolver
	logger   *slog.Logger
	port     int
}

// NewServer creates a new GraphQL server.
func NewServer(ffi FFIClient, port int, logger *slog.Logger) *Server {
	return &Server{
		resolver: NewResolver(ffi),
		logger:   logger,
		port:     port,
	}
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// Register GraphQL endpoint
	mux.HandleFunc("/graphql", s.graphqlHandler)

	// Register health check endpoint
	mux.HandleFunc("/healthz", s.healthzHandler)

	addr := fmt.Sprintf(":%d", s.port)
	s.logger.Info("Starting GraphQL server", "address", addr)

	return http.ListenAndServe(addr, loggingMiddleware(s.logger)(mux))
}

// graphqlHandler handles GraphQL queries and mutations.
func (s *Server) graphqlHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "GraphQL only accepts POST requests", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var req struct {
		Query         string                 `json:"query"`
		OperationName string                 `json:"operationName"`
		Variables     map[string]interface{} `json:"variables"`
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Error("failed to read request body", "error", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if err := json.Unmarshal(body, &req); err != nil {
		s.logger.Error("failed to parse GraphQL request", "error", err)
		http.Error(w, "Invalid GraphQL request", http.StatusBadRequest)
		return
	}

	// Execute GraphQL query (simplified — real implementation would use gqlgen)
	result := s.executeQuery(r.Context(), req.Query, req.Variables)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// healthzHandler returns the health status.
func (s *Server) healthzHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET requests allowed", http.StatusMethodNotAllowed)
		return
	}

	status, err := s.resolver.Healthz()
	if err != nil {
		s.logger.Error("health check failed", "error", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "Unhealthy: %v", err)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Healthy: %s", status)
}

// executeQuery executes a GraphQL query (simplified version).
// In a real implementation, this would use gqlgen.
func (s *Server) executeQuery(ctx context.Context, query string, variables map[string]interface{}) map[string]interface{} {
	// This is a placeholder. In production, gqlgen would handle this.
	return map[string]interface{}{
		"data":   nil,
		"errors": []map[string]interface{}{{"message": "GraphQL execution not yet implemented"}},
	}
}

// loggingMiddleware logs HTTP requests and responses.
func loggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Create a response writer wrapper to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)
			logger.LogAttrs(
				context.Background(),
				slog.LevelInfo,
				"HTTP request",
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", wrapped.statusCode),
				slog.Duration("duration", duration),
			)
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if w.statusCode == http.StatusOK {
		w.statusCode = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}
