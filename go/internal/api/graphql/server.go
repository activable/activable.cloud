package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
	"golang.org/x/time/rate"
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

	// Register GraphQL endpoint with rate limiter
	mux.Handle("/graphql", s.rateLimiter(http.HandlerFunc(s.graphqlHandler)))

	// Register health check endpoint
	mux.HandleFunc("/healthz", s.healthzHandler)

	addr := fmt.Sprintf(":%d", s.port)
	s.logger.Info("Starting GraphQL server", "address", addr)

	return http.ListenAndServe(addr, loggingMiddleware(s.logger)(mux))
}

// graphqlHandler handles GraphQL queries using the resolver methods.
// This leverages the resolver methods wired via schema.resolvers.go.
func (s *Server) graphqlHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "GraphQL only accepts POST requests", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body (limited to 1MB to prevent OOM attacks)
	var req struct {
		Query         string                 `json:"query"`
		OperationName string                 `json:"operationName"`
		Variables     map[string]interface{} `json:"variables"`
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	defer func() { _ = r.Body.Close() }()

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to parse GraphQL request", "error", err)
		http.Error(w, "Invalid GraphQL request", http.StatusBadRequest)
		return
	}

	// Execute the query through the schema resolvers
	ctx := r.Context()
	result := s.executeQuery(ctx, req.Query, req.Variables)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		s.logger.Error("failed to encode GraphQL response", "error", err)
	}
}

// schemaSource is the GraphQL SDL loaded once for query validation.
var schemaSource = `
schema { query: Query; mutation: Mutation }
type Query {
  findNode(label: String!, id: String!): Node
  walkEdges(start: String!, edgeTypes: [String!]!, direction: String!, depth: Int!): [NodeRef!]!
  pathFinder(start: String!, end: String!, edgePattern: [String!]!, maxHops: Int!): [Path!]!
  blastRadius(node: String!, depth: Int!): [NodeRef!]!
  subgraph(center: String!, radius: Int!): Subgraph!
  ingestStatus(runId: String!): IngestRun
  healthz: String!
}
type Mutation {
  triggerIngest(provider: String!, regions: [String!]!): IngestRun!
}
type Node { id: String!; label: String!; properties: String }
type NodeRef { id: String!; label: String! }
type Edge { from: String!; to: String!; type: String!; properties: String }
type Path { nodes: [NodeRef!]!; edges: [Edge!]!; length: Int! }
type Subgraph { center: NodeRef!; nodes: [NodeRef!]! }
type IngestRun { id: String!; status: String!; startedAt: String!; services: [IngestService!]! }
type IngestService { name: String!; status: String!; nodeCount: Int!; edgeCount: Int!; error: String }
`

// executeQuery parses a GraphQL query using gqlparser AST, extracts the
// operation field, and dispatches to the appropriate resolver method.
// This replaces the unsafe string-matching dispatcher with proper parsing.
func (s *Server) executeQuery(ctx context.Context, query string, variables map[string]any) map[string]any {
	// Parse the schema (could be cached, but it's fast enough for v1)
	schema, schemaErr := gqlparser.LoadSchema(&ast.Source{Name: "schema.graphql", Input: schemaSource})
	if schemaErr != nil {
		return gqlError(fmt.Sprintf("schema load error: %v", schemaErr))
	}

	// Parse the query against the schema
	doc, parseErrs := gqlparser.LoadQueryWithRules(schema, query, nil)
	if parseErrs != nil {
		return gqlError(fmt.Sprintf("query parse error: %v", parseErrs))
	}

	if len(doc.Operations) == 0 {
		return gqlError("no operation found in query")
	}

	operation := doc.Operations[0]
	if len(operation.SelectionSet) == 0 {
		return gqlError("empty selection set")
	}

	// Get the first field in the selection set
	field, ok := operation.SelectionSet[0].(*ast.Field)
	if !ok {
		return gqlError("unsupported selection type")
	}

	// Extract arguments from AST
	args := make(map[string]any)
	for _, arg := range field.Arguments {
		args[arg.Name] = resolveValue(arg.Value, variables)
	}

	// Dispatch based on operation type + field name
	queryResolver := s.resolver.Query()
	mutationResolver := s.resolver.Mutation()

	switch operation.Operation {
	case ast.Query:
		return s.dispatchQuery(ctx, field.Name, args, queryResolver)
	case ast.Mutation:
		return s.dispatchMutation(ctx, field.Name, args, mutationResolver)
	default:
		return gqlError(fmt.Sprintf("unsupported operation: %s", operation.Operation))
	}
}

// dispatchQuery routes a parsed query field to the correct resolver method.
func (s *Server) dispatchQuery(ctx context.Context, fieldName string, args map[string]any, resolver QueryResolver) map[string]any {
	switch fieldName {
	case "findNode":
		result, err := resolver.FindNode(ctx, argString(args, "label"), argString(args, "id"))
		if err != nil {
			return gqlError(err.Error())
		}
		return gqlData(fieldName, result)

	case "walkEdges":
		result, err := resolver.WalkEdges(ctx, argString(args, "start"), argStringSlice(args, "edgeTypes"), argString(args, "direction"), argInt(args, "depth"))
		if err != nil {
			return gqlError(err.Error())
		}
		return gqlData(fieldName, result)

	case "pathFinder":
		result, err := resolver.PathFinder(ctx, argString(args, "start"), argString(args, "end"), argStringSlice(args, "edgePattern"), argInt(args, "maxHops"))
		if err != nil {
			return gqlError(err.Error())
		}
		return gqlData(fieldName, result)

	case "blastRadius":
		result, err := resolver.BlastRadius(ctx, argString(args, "node"), argInt(args, "depth"))
		if err != nil {
			return gqlError(err.Error())
		}
		return gqlData(fieldName, result)

	case "subgraph":
		result, err := resolver.Subgraph(ctx, argString(args, "center"), argInt(args, "radius"))
		if err != nil {
			return gqlError(err.Error())
		}
		return gqlData(fieldName, result)

	case "ingestStatus":
		result, err := resolver.IngestStatus(ctx, argString(args, "runId"))
		if err != nil {
			return gqlError(err.Error())
		}
		return gqlData(fieldName, result)

	case "healthz":
		result, err := resolver.Healthz(ctx)
		if err != nil {
			return gqlError(err.Error())
		}
		return gqlData(fieldName, result)

	case "__schema":
		return gqlData("__schema", map[string]any{
			"queryType":    map[string]any{"name": "Query"},
			"mutationType": map[string]any{"name": "Mutation"},
		})

	default:
		return gqlError(fmt.Sprintf("unknown query field: %s", fieldName))
	}
}

// dispatchMutation routes a parsed mutation field to the correct resolver method.
func (s *Server) dispatchMutation(ctx context.Context, fieldName string, args map[string]any, resolver MutationResolver) map[string]any {
	switch fieldName {
	case "triggerIngest":
		result, err := resolver.TriggerIngest(ctx, argString(args, "provider"), argStringSlice(args, "regions"))
		if err != nil {
			return gqlError(err.Error())
		}
		return gqlData(fieldName, result)

	default:
		return gqlError(fmt.Sprintf("unknown mutation field: %s", fieldName))
	}
}

func gqlData(field string, data any) map[string]any {
	return map[string]any{"data": map[string]any{field: data}}
}

func gqlError(message string) map[string]any {
	return map[string]any{"data": nil, "errors": []map[string]any{{"message": message}}}
}

// resolveValue converts a gqlparser AST value to a Go value.
func resolveValue(value *ast.Value, variables map[string]any) any {
	if value == nil {
		return nil
	}
	switch value.Kind {
	case ast.Variable:
		if v, ok := variables[value.Raw]; ok {
			return v
		}
		return nil
	case ast.IntValue:
		var n int
		_, _ = fmt.Sscanf(value.Raw, "%d", &n)
		return n
	case ast.StringValue, ast.BlockValue, ast.EnumValue:
		return value.Raw
	case ast.ListValue:
		var items []any
		for _, child := range value.Children {
			items = append(items, resolveValue(child.Value, variables))
		}
		return items
	default:
		return value.Raw
	}
}

// Argument extraction helpers with type-safe defaults.

func argString(args map[string]any, key string) string {
	if v, ok := args[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func argInt(args map[string]any, key string) int {
	if v, ok := args[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case float64:
			return int(n)
		}
	}
	return 0
}

func argStringSlice(args map[string]any, key string) []string {
	if v, ok := args[key]; ok {
		switch items := v.(type) {
		case []any:
			result := make([]string, 0, len(items))
			for _, item := range items {
				if s, ok := item.(string); ok {
					result = append(result, s)
				}
			}
			return result
		case []string:
			return items
		}
	}
	return nil
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
		_, _ = fmt.Fprintf(w, "Unhealthy: %v", err)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "Healthy: %s", status)
}

// rateLimiter returns middleware that rate-limits requests per IP address.
// Configured at 100 requests per minute with burst of 10.
func (s *Server) rateLimiter(next http.Handler) http.Handler {
	type client struct {
		limiter  *rate.Limiter
		lastSeen time.Time
	}

	var (
		mu      sync.Mutex
		clients = make(map[string]*client)
	)

	// Clean up stale entries every 3 minutes
	go func() {
		for {
			time.Sleep(3 * time.Minute)
			mu.Lock()
			for ip, c := range clients {
				if time.Since(c.lastSeen) > 5*time.Minute {
					delete(clients, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract IP without port
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		mu.Lock()
		if _, exists := clients[ip]; !exists {
			// 100 requests per minute = 100/60 per second ≈ 1.667 per second
			clients[ip] = &client{
				limiter: rate.NewLimiter(rate.Limit(100.0/60.0), 10),
			}
		}
		clients[ip].lastSeen = time.Now()
		limiter := clients[ip].limiter
		mu.Unlock()

		if !limiter.Allow() {
			s.logger.Warn("rate limit exceeded", "ip", ip)
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
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
