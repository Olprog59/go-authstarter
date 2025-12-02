package web

import (
	"net/http"
	"time"

	"github.com/Olprog59/go-authstarter/internal/app"
	"github.com/Olprog59/go-authstarter/internal/config"
	"github.com/Olprog59/go-authstarter/internal/domain"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewMux creates and configures the HTTP router / Crée et configure le routeur HTTP
func NewMux(h *Handler, conf *config.Config, container *app.Container) http.Handler {
	mux := http.NewServeMux()
	mw := NewMiddleware(conf, container.Metrics, container.UserRepo)

	// Health check endpoints (no auth, no rate limiting for load balancers)
	// These endpoints are typically called frequently by monitoring systems
	// Note: SecurityHeaders is applied globally below, so no need to add it here
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

// chain applies middleware to HTTP handler / Applique les middlewares au gestionnaire HTTP
func chain(f http.HandlerFunc, mw *Middleware, middlewares ...func(http.Handler) http.Handler) http.Handler {
	var handler http.Handler = f

	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}

	return handler
}
