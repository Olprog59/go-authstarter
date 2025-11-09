package web

import (
	"net/http"

	"github.com/Olprog59/go-fun/internal/config"
)

// NewMux creates and configures the main HTTP request router (multiplexer) for the application.
// It defines all the API endpoints and chains them with the necessary middleware for security,
// logging, rate limiting, and authentication.
//
// The function follows a structured approach to middleware application:
// 1.  **Endpoint-Specific Middleware**: Routes like /api/login, /api/register, and /api/refresh
//     are wrapped with strict rate limiting. Protected routes like /api/me are additionally
//     wrapped with authentication (Auth) and CSRF protection.
// 2.  **Global Middleware**: After defining individual routes, the entire multiplexer is wrapped
//     in a series of global middlewares that apply to all incoming requests. These include:
//     - A global rate limiter as a safety net.
//     - Security headers to protect against common web vulnerabilities.
//     - CORS handling to allow cross-origin requests from configured domains.
//     - Request logging to provide visibility into traffic.
//
// The `chain` helper function is used to apply middleware in a readable, declarative way.
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

	// Global middlewares
	var handler http.Handler = mux
	handler = mw.RateLimit(handler)
	handler = mw.SecurityHeaders(handler)
	handler = mw.Cors(handler)
	handler = Logging(handler)

	return handler
}

// chain is a helper function that applies a series of middleware to an HTTP handler.
// It takes a final handler function (the endpoint logic) and a list of middleware functions.
// The middlewares are applied in reverse order of how they are passed, which means
// they execute from left to right as they appear in the function call.
//
// For example, `chain(myHandler, middleware1, middleware2)` will result in a flow where
// an incoming request first passes through `middleware1`, then `middleware2`, and finally
// reaches `myHandler`. This right-to-left application makes the code read more naturally.
func chain(f http.HandlerFunc, mw *Middleware, middlewares ...func(http.Handler) http.Handler) http.Handler {
	var handler http.Handler = f

	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}

	return handler
}
