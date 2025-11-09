package web

import (
	"net/http"

	"github.com/Olprog59/go-fun/internal/config"
)

func NewMux(h *Handler, conf *config.Config) http.Handler {
	mux := http.NewServeMux()
	mw := NewMiddleware(conf)

	mux.Handle("POST /api/login", chain(h.Login, mw, mw.RateLimitStrict))
	mux.Handle("POST /api/register", chain(h.Register, mw, mw.RateLimitStrict))

	mux.Handle("GET /verify", chain(h.VerifyEmail, mw, mw.RateLimitStrict))

	mux.Handle("POST /api/resend-verification", chain(h.ResendVerification, mw, mw.RateLimitStrict))

	mux.Handle("POST /api/refresh", chain(h.RefreshToken, mw, mw.Auth, mw.CSRF, mw.RateLimitStrict))

	mux.Handle("GET /api/me", chain(h.Me, mw, mw.Auth, mw.CSRF, mw.RateLimitByUser))
	mux.Handle("GET /{$}", chain(h.Home, mw, mw.Auth, mw.RateLimitByUser))

	// Middlewares globaux
	var handler http.Handler = mux
	handler = mw.RateLimit(handler)
	handler = mw.SecurityHeaders(handler)
	handler = mw.Cors(handler)
	handler = Logging(handler)

	return handler
}

// chain applique les middlewares de droite à gauche (comme on les lit)
func chain(f http.HandlerFunc, mw *Middleware, middlewares ...func(http.Handler) http.Handler) http.Handler {
	var handler http.Handler = f

	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}

	return handler
}
