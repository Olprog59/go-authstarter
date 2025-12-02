package web

import (
	"encoding/json"
	"net/http"

	"github.com/Olprog59/go-authstarter/internal/app"
)

// Handler is a container for application dependencies that are required by HTTP handlers.
// By embedding the application's dependency injection container, it provides handlers
// with access to services, repositories, and configuration.
type Handler struct {
	container *app.Container
}

// NewHandler creates and returns a new Handler instance.
// It takes the application's dependency injection container as a parameter,
// making it available to all HTTP handlers attached to this Handler.
func NewHandler(container *app.Container) *Handler {
	return &Handler{container: container}
}

// ErrorResponse is a helper function for sending standardized JSON error responses.
// It sets the "Content-Type" header to "application/json", writes the specified HTTP status code,
// and sends a JSON body with an "error" key containing the provided message.
func ErrorResponse(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{
		"error": message,
	})
}

// jsonResponse is a helper function for sending standardized JSON responses.
// It sets the "Content-Type" header to "application/json" and encodes the provided
// data structure into a JSON response body.
func jsonResponse(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// limitRequestBody wraps a request body with MaxBytesReader to limit its size.
// This prevents DoS attacks via large request bodies. Returns true if the body
// is within the limit, false if it exceeds it (and writes an error response).
//
// Parameters:
//   - w: http.ResponseWriter for error responses
//   - r: *http.Request to limit
//   - maxBytes: Maximum allowed body size in bytes (e.g., 1MB = 1024*1024)
//
// Returns:
//   - bool: true if body is within limit, false if exceeded (caller should return)
//
// Example usage:
//
//	func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
//	    if !limitRequestBody(w, r, 1*1024*1024) { // 1MB limit
//	        return // Error already written
//	    }
//	    // Continue with normal processing
//	}
func limitRequestBody(w http.ResponseWriter, r *http.Request, maxBytes int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	return true
}
