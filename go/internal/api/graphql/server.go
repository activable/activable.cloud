package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
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

	// Limit request body to 1MB to prevent OOM attacks
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
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

// executeQuery parses a GraphQL query string and dispatches to resolver methods.
// This is a lightweight hand-rolled dispatcher — production would use gqlgen.
// It handles the 5 queries + 2 mutations defined in schema.graphql.
func (s *Server) executeQuery(ctx context.Context, query string, variables map[string]interface{}) map[string]interface{} {
	q := strings.TrimSpace(query)

	// Detect mutation vs query
	if strings.HasPrefix(q, "mutation") {
		return s.executeMutation(ctx, q, variables)
	}

	// Strip "query" prefix and outer braces
	q = strings.TrimPrefix(q, "query")
	q = strings.TrimSpace(q)
	// Remove operation name if present (e.g., "MyQuery { ... }")
	if idx := strings.Index(q, "{"); idx >= 0 {
		q = q[idx:]
	}

	// Route based on which field is requested
	switch {
	case strings.Contains(q, "findNode"):
		label := extractStringArg(q, "label")
		id := extractStringArg(q, "id")
		result, err := s.resolver.FindNode(label, id)
		if err != nil {
			return gqlError(err.Error())
		}
		return gqlData("findNode", result)

	case strings.Contains(q, "walkEdges"):
		startId := extractStringArg(q, "startId")
		edgeTypes := extractArrayArg(q, "edgeTypes")
		direction := extractStringArg(q, "direction")
		depth := extractIntArg(q, "depth")
		result, err := s.resolver.WalkEdges(startId, edgeTypes, direction, depth)
		if err != nil {
			return gqlError(err.Error())
		}
		return gqlData("walkEdges", result)

	case strings.Contains(q, "pathFinder"):
		startId := extractStringArg(q, "startId")
		endId := extractStringArg(q, "endId")
		edgeTypes := extractArrayArg(q, "edgeTypes")
		maxHops := extractIntArg(q, "maxHops")
		result, err := s.resolver.PathFinder(startId, endId, edgeTypes, maxHops)
		if err != nil {
			return gqlError(err.Error())
		}
		return gqlData("pathFinder", result)

	case strings.Contains(q, "blastRadius"):
		nodeId := extractStringArg(q, "nodeId")
		maxHops := extractIntArg(q, "maxHops")
		result, err := s.resolver.BlastRadius(nodeId, maxHops)
		if err != nil {
			return gqlError(err.Error())
		}
		return gqlData("blastRadius", result)

	case strings.Contains(q, "subgraph"):
		centerId := extractStringArg(q, "centerId")
		radius := extractIntArg(q, "radius")
		result, err := s.resolver.Subgraph(centerId, radius)
		if err != nil {
			return gqlError(err.Error())
		}
		return gqlData("subgraph", result)

	case strings.Contains(q, "ingestStatus"):
		runId := extractStringArg(q, "runId")
		result, err := s.resolver.IngestStatus(runId)
		if err != nil {
			return gqlError(err.Error())
		}
		return gqlData("ingestStatus", result)

	case strings.Contains(q, "__schema"):
		return gqlData("__schema", map[string]any{
			"queryType":    map[string]any{"name": "Query"},
			"mutationType": map[string]any{"name": "Mutation"},
		})

	default:
		return gqlError(fmt.Sprintf("unrecognized query field in: %s", q[:min(len(q), 100)]))
	}
}

func (s *Server) executeMutation(ctx context.Context, q string, variables map[string]interface{}) map[string]interface{} {
	switch {
	case strings.Contains(q, "triggerIngest"):
		provider := extractStringArg(q, "provider")
		regions := extractArrayArg(q, "regions")
		result, err := s.resolver.TriggerIngest(provider, regions)
		if err != nil {
			return gqlError(err.Error())
		}
		return gqlData("triggerIngest", result)

	default:
		return gqlError("unrecognized mutation")
	}
}

func gqlData(field string, data any) map[string]interface{} {
	return map[string]interface{}{
		"data": map[string]interface{}{field: data},
	}
}

func gqlError(msg string) map[string]interface{} {
	return map[string]interface{}{
		"data":   nil,
		"errors": []map[string]interface{}{{"message": msg}},
	}
}

// extractStringArg extracts a string argument value from a raw GraphQL query.
// Looks for: argName: "value" or argName: \"value\"
func extractStringArg(q, argName string) string {
	patterns := []string{
		argName + `: "`,
		argName + `: \"`,
		argName + `:"`,
	}
	for _, prefix := range patterns {
		idx := strings.Index(q, prefix)
		if idx < 0 {
			continue
		}
		start := idx + len(prefix)
		// Find closing quote
		for end := start; end < len(q); end++ {
			if q[end] == '"' || (q[end] == '\\' && end+1 < len(q) && q[end+1] == '"') {
				if q[end] == '"' {
					return q[start:end]
				}
				end++ // skip escaped quote
			}
		}
		// No closing quote found — return what we have until next special char
		end := strings.IndexAny(q[start:], `")\}`)
		if end >= 0 {
			return q[start : start+end]
		}
	}
	return ""
}

// extractIntArg extracts an integer argument from a raw GraphQL query.
func extractIntArg(q, argName string) int {
	patterns := []string{argName + `: `, argName + `:`}
	for _, prefix := range patterns {
		idx := strings.Index(q, prefix)
		if idx < 0 {
			continue
		}
		start := idx + len(prefix)
		// Read digits
		end := start
		for end < len(q) && q[end] >= '0' && q[end] <= '9' {
			end++
		}
		if end > start {
			val := 0
			for _, c := range q[start:end] {
				val = val*10 + int(c-'0')
			}
			return val
		}
	}
	return 0
}

// extractArrayArg extracts a string array argument like: edgeTypes: ["a", "b"]
func extractArrayArg(q, argName string) []string {
	idx := strings.Index(q, argName+":")
	if idx < 0 {
		return nil
	}
	sub := q[idx:]
	open := strings.Index(sub, "[")
	if open < 0 {
		return nil
	}
	close := strings.Index(sub[open:], "]")
	if close < 0 {
		return nil
	}
	inner := sub[open+1 : open+close]
	var result []string
	for _, part := range strings.Split(inner, ",") {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `"\"`)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
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
