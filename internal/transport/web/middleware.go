package web

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Olprog59/go-fun/internal/config"
	"github.com/Olprog59/go-fun/internal/service/auth"
)

type key int

const (
	bearerPrefix     = "Bearer "
	claimsKey    key = 0
)

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
		authorization := r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")

		// Validation plus robuste
		if len(authorization) < len(bearerPrefix) || !strings.HasPrefix(authorization, bearerPrefix) {
			ErrorResponse(w, `{"error":"forbidden"}`, http.StatusInternalServerError)
			return
		}

		claims, err := auth.ValidateJWT(authorization[7:], config.NewEnv().JWTToken)
		if err != nil {
			ErrorResponse(w, err.Error(), http.StatusInternalServerError)
			return
		}

		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
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
