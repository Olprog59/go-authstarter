package http

import (
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const bearerPrefix = "Bearer token-for-"

func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)

		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"duration", time.Since(start),
		)
	})
}

func Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")

		// Validation plus robuste
		if len(auth) < len(bearerPrefix) || !strings.HasPrefix(auth, bearerPrefix) {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Helper pour chaîner les middlewares
func chain(h http.HandlerFunc, middlewares ...func(http.Handler) http.Handler) http.Handler {
	handler := http.Handler(h)
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	return handler
}
