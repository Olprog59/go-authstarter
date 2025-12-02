package web

import (
	"net/http"
	"time"

	"github.com/Olprog59/go-fun/internal/app"
	"github.com/Olprog59/go-fun/internal/config"
	"github.com/Olprog59/go-fun/internal/domain"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewMux creates and configures the main HTTP request router (multiplexer) for the application.
// It defines all the API endpoints and chains them with the necessary middleware for security,
// logging, rate limiting, and authentication.
//
// The function follows a structured approach to middleware application:
//  1. **Endpoint-Specific Middleware**: Routes like /api/login, /api/register, and /api/refresh
//     are wrapped with strict rate limiting. Protected routes like /api/me are additionally
//     wrapped with authentication (Auth) and CSRF protection.
//  2. **Global Middleware**: After defining individual routes, the entire multiplexer is wrapped
//     in a series of global middlewares that apply to all incoming requests. These include:
//     - A global rate limiter as a safety net.
//     - Security headers to protect against common web vulnerabilities.
//     - CORS handling to allow cross-origin requests from configured domains.
//     - Request logging to provide visibility into traffic.
//
// The `chain` helper function is used to apply middleware in a readable, declarative way.
func NewMux(h *Handler, conf *config.Config, container *app.Container) http.Handler {
	mux := http.NewServeMux()
	mw := NewMiddleware(conf, container.Metrics, container.UserRepo)

	// Health check endpoints (no auth, no rate limiting for load balancers)
	// These endpoints are typically called frequently by monitoring systems
	mux.HandleFunc("GET /health", h.HealthCheck)
	mux.HandleFunc("GET /readiness", h.ReadinessCheck)

	// Prometheus metrics endpoint (protected - requires admin authentication)
	// This endpoint exposes internal system metrics and should only be accessible to administrators
	// If you need Prometheus to scrape without auth, consider:
	// 1. Running metrics on a separate internal port
	// 2. Using IP whitelisting at infrastructure level
	// 3. Using service mesh with mTLS
	mux.Handle("GET /metrics", chain(
		func(w http.ResponseWriter, r *http.Request) {
			promhttp.Handler().ServeHTTP(w, r)
		},
		mw,
		mw.Auth,
		mw.RequirePermission(domain.PermissionStatsRead.String()),
	))

	mux.Handle("POST /api/login", chain(h.Login, mw, mw.RateLimitStrict))
	mux.Handle("POST /api/register", chain(h.Register, mw, mw.RateLimitStrict))

	mux.Handle("GET /verify", chain(h.VerifyEmail, mw, mw.RateLimitStrict))

	mux.Handle("POST /api/resend-verification", chain(h.ResendVerification, mw, mw.RateLimitStrict))

	// Password reset endpoints (public, with rate limiting to prevent abuse)
	mux.Handle("POST /api/request-password-reset", chain(h.RequestPasswordReset, mw, mw.RateLimitStrict))
	mux.Handle("POST /api/reset-password", chain(h.ResetPassword, mw, mw.RateLimitStrict))

	mux.Handle("POST /api/refresh", chain(h.RefreshToken, mw, mw.Auth, mw.CSRF, mw.RateLimitStrict))

	// Protected user endpoints
	mux.Handle("GET /api/me", chain(h.Me, mw, mw.Auth, mw.CSRF, mw.RateLimitByUser))
	mux.Handle("POST /api/logout", chain(h.Logout, mw, mw.Auth, mw.CSRF, mw.RateLimitByUser))
	mux.Handle("GET /{$}", chain(h.Home, mw, mw.Auth, mw.RateLimitByUser))

	// Admin endpoints - using granular permissions
	// These endpoints require authentication + CSRF + specific permission
	mux.Handle("GET /api/admin/users", chain(h.ListUsers, mw, mw.Auth, mw.CSRF, mw.RequirePermission(domain.PermissionUsersList.String())))
	mux.Handle("DELETE /api/admin/users/{id}", chain(h.DeleteUser, mw, mw.Auth, mw.CSRF, mw.RequirePermission(domain.PermissionUsersDelete.String())))
	mux.Handle("PATCH /api/admin/users/{id}/role", chain(h.UpdateUserRole, mw, mw.Auth, mw.CSRF, mw.RequirePermission(domain.PermissionRolesWrite.String())))

	// Moderator endpoints - using granular permissions
	// Moderators and admins can access these (based on their permissions)
	mux.Handle("GET /api/moderator/stats", chain(h.GetUserStats, mw, mw.Auth, mw.CSRF, mw.RequirePermission(domain.PermissionStatsRead.String())))

	// Global middlewares - applied in reverse order / Middlewares globaux appliqués en ordre inverse
	var handler http.Handler = mux
	handler = mw.MetricsMiddleware(handler) // Metrics first to capture everything
	handler = mw.RateLimit(handler)
	handler = mw.SecurityHeaders(handler)
	handler = mw.Cors(handler)
	handler = Timeout(30 * time.Second)(handler) // 30s timeout for all requests / Timeout de 30s pour toutes les requêtes
	handler = Logging(handler)                   // Logging includes request ID
	handler = RequestID(handler)                 // RequestID first - generates ID for all middleware

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
