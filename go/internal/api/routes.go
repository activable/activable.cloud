package api

import (
	"net/http"
)

// Routes defines the HTTP server routes.
type Routes struct {
	mux *http.ServeMux
}

// NewRoutes creates a new Routes instance.
func NewRoutes() *Routes {
	return &Routes{
		mux: http.NewServeMux(),
	}
}

// ServeHTTP implements http.Handler interface.
func (r *Routes) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}
