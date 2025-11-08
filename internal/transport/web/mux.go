package web

import (
	"net/http"

	"github.com/Olprog59/go-fun/internal/config"
)

func NewMux(h *Handler, conf *config.Config) http.Handler {
	mux := http.NewServeMux()
	mw := NewMiddleware(conf)

	// Endpoints d'authentification - TRÈS stricte (2 req/s, burst 5)
	mux.Handle("POST /api/login", chain(h.Login, mw, mw.RateLimitStrict))
	mux.Handle("POST /api/register", chain(h.Register, mw, mw.RateLimitStrict))

	// Vérification email - strict
	mux.Handle("GET /verify", chain(h.VerifyEmail, mw, mw.RateLimitStrict))

	// Refresh token - strict mais après auth
	mux.Handle("POST /api/refresh", chain(h.RefreshToken, mw, mw.Auth, mw.RateLimitStrict))

	// Routes utilisateur - rate limit par user (20 req/s, burst 40)
	mux.Handle("GET /api/me", chain(h.Me, mw, mw.Auth, mw.RateLimitByUser))
	mux.Handle("GET /{$}", chain(h.Home, mw, mw.Auth, mw.RateLimitByUser))

	// Middlewares globaux
	var handler http.Handler = mux
	handler = mw.RateLimit(handler) // Filet de sécurité global (10 req/s)
	handler = mw.SecurityHeaders(handler)
	handler = mw.Cors(handler)
	handler = Logging(handler)

	return handler
}

// chain applique les middlewares de droite à gauche (comme on les lit)
func chain(f http.HandlerFunc, mw *Middleware, middlewares ...func(http.Handler) http.Handler) http.Handler {
	var handler http.Handler = f

	// Applique les middlewares de droite à gauche
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}

	return handler
}
