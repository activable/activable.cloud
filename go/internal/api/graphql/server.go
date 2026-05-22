package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Server implements the GraphQL API server.
type Server struct {
	addr   string
	logger *slog.Logger
	ffi    FFIClient
}

// NewServer creates a new GraphQL server with real FFI.
func NewServer(addr string, logger *slog.Logger) *Server {
	return &Server{
		addr:   addr,
		logger: logger,
		ffi:    &RealFFIClient{},
	}
}

// NewServerWithFFI creates a new GraphQL server with a custom FFI client (for testing).
func NewServerWithFFI(addr string, logger *slog.Logger, ffi FFIClient) *Server {
	return &Server{
		addr:   addr,
		logger: logger,
		ffi:    ffi,
	}
}

// Start starts the GraphQL server.
func (s *Server) Start() error {
	resolver := NewResolverWithFFI(s.logger, s.ffi, "default")

	// Set up HTTP routes
	mux := http.NewServeMux()

	// GraphQL endpoint
	mux.HandleFunc("/graphql", s.graphqlHandler(resolver))

	// GraphQL Playground
	mux.HandleFunc("/", s.playgroundHandler())

	// Health check
	mux.HandleFunc("/healthz", s.healthCheckHandler())

	s.logger.Info("Starting GraphQL server", "addr", s.addr)
	return http.ListenAndServe(s.addr, s.loggingMiddleware(mux))
}

// graphqlHandler handles GraphQL queries and mutations.
func (s *Server) graphqlHandler(resolver *Resolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		defer func() {
			duration := time.Since(start)
			s.logger.InfoContext(r.Context(), "GraphQL request",
				"method", r.Method,
				"path", r.URL.Path,
				"duration_ms", duration.Milliseconds(),
				"status", http.StatusOK,
			)
		}()

		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var query struct {
			Query         string                 `json:"query"`
			OperationName string                 `json:"operationName"`
			Variables     map[string]interface{} `json:"variables"`
		}

		if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
			http.Error(w, fmt.Sprintf("bad request: %v", err), http.StatusBadRequest)
			return
		}

		// For now, return a simple error response indicating GraphQL is mounted.
		// In production, you would use a full GraphQL library (gqlgen, graphql-go, etc.).
		result := map[string]interface{}{
			"errors": []map[string]string{
				{
					"message": "GraphQL queries not yet fully implemented; mounted at /graphql",
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(result)
	}
}

// playgroundHandler serves the GraphQL Playground.
func (s *Server) playgroundHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, playgroundHTML)
	}
}

// healthCheckHandler checks database and FFI connectivity.
func (s *Server) healthCheckHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Check FFI health
		healthResult := s.ffi.HealthCheck()
		if healthResult != "ok" {
			s.logger.ErrorContext(ctx, "Health check failed", "error", healthResult)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{
				"status": "unhealthy",
				"error":  healthResult,
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	}
}

// loggingMiddleware adds structured logging to all requests.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &statusWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)
		s.logger.InfoContext(r.Context(), "HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"query", r.URL.RawQuery,
			"remote_addr", r.RemoteAddr,
			"status", wrapped.statusCode,
			"duration_ms", duration.Milliseconds(),
		)
	})
}

// statusWriter wraps http.ResponseWriter to capture the status code.
type statusWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *statusWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

// playgroundHTML is the GraphQL Playground HTML.
const playgroundHTML = `
<!DOCTYPE html>
<html>
<head>
	<title>GraphQL Playground</title>
	<meta charset=utf-8/>
	<meta name="viewport" content="width=device-width, initial-scale=1"/>
	<link rel="stylesheet" href="//cdn.jsdelivr.net/npm/graphql-playground-react/build/static/css/index.css"/>
	<link rel="shortcut icon" href="//cdn.jsdelivr.net/npm/graphql-playground-react/build/favicon.png"/>
	<script src="//cdn.jsdelivr.net/npm/graphql-playground-react/build/static/js/middleware.js"></script>
</head>
<body>
	<div id="root"></div>
	<script>
		window.addEventListener('load', function (event) {
			GraphQLPlayground.init(document.getElementById('root'), {
				endpoint: '/graphql',
				subscriptionEndpoint: '/graphql',
			})
		})
	</script>
</body>
</html>
`
