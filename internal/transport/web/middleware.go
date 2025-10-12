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
		w.Header().Set("Content-Type", "application/json")

		var tokenStr string

		// Tenter de récupérer le token depuis le cookie
		if cookie, err := r.Cookie("access_token"); err == nil {
			tokenStr = cookie.Value
		} else {
			// Sinon essayer le header Authorization Bearer
			authorization := r.Header.Get("Authorization")
			const bearerPrefix = "Bearer "
			if len(authorization) < len(bearerPrefix) || !strings.HasPrefix(authorization, bearerPrefix) {
				ErrorResponse(w, `{"error":"forbidden"}`, http.StatusUnauthorized)
				return
			}
			tokenStr = authorization[len(bearerPrefix):]
		}

		claims, err := auth.ValidateJWT(tokenStr, config.NewEnv().JWTKey)
		if err != nil {
			ErrorResponse(w, err.Error(), http.StatusUnauthorized)
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

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Autoriser l’origine de votre frontend
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
		// Autoriser les méthodes HTTP utilisées
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		// Autoriser ces headers CORS spécifiques
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		// Important si vous utilisez les cookies HTTP-only et authentification
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// Répondre directement aux requêtes OPTIONS (préflight)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Passer au handler suivant pour toutes les autres requêtes
		next.ServeHTTP(w, r)
	})
}
