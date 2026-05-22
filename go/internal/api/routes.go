package api

import (
	"log/slog"
	"net/http"

	"github.com/activable-cloud/activable.cloud/go/internal/api/graphql"
)

// Routes defines the HTTP server routes.
type Routes struct {
	graphQLResolver *graphql.Resolver
	logger          *slog.Logger
}

// NewRoutes creates a new Routes instance.
func NewRoutes(logger *slog.Logger) *Routes {
	return &Routes{
		graphQLResolver: graphql.NewResolver(logger),
		logger:          logger,
	}
}

// Register registers all routes with the provided multiplexer.
func (r *Routes) Register(mux *http.ServeMux) {
	// GraphQL routes are registered by the server in graphql/server.go
	// This function is available for future REST endpoints if needed.
}
