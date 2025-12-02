package web

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Olprog59/go-fun/internal/config"
	"github.com/Olprog59/go-fun/internal/domain"
	"github.com/Olprog59/go-fun/internal/metrics"
	"github.com/Olprog59/go-fun/internal/ports"
	"github.com/Olprog59/go-fun/internal/service/auth"
	"github.com/google/uuid"
)

const (
	bearerPrefix     = "Bearer "   // Standard prefix for Bearer tokens in Authorization headers.
	RequestIDKey     = "request_id" // Context key for request ID
	RequestIDHeader  = "X-Request-ID" // HTTP header name for request ID
)

type contextKey string

const requestIDContextKey contextKey = "request_id"

// RequestID is a middleware that generates a unique ID for each HTTP request.
// This ID is used for log correlation, tracing, and debugging across distributed systems.
//
// The middleware performs the following:
// 1. Checks if an X-Request-ID header is already present (from proxy/load balancer)
// 2. If not present, generates a new UUID v4
// 3. Adds the request ID to the request context for use in handlers and services
// 4. Includes the request ID in the response headers for client-side correlation
//
// This enables tracing a single request through logs, error reports, and monitoring systems.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if request ID is already provided (from proxy/load balancer)
		requestID := r.Header.Get(RequestIDHeader)
		if requestID == "" {
			// Generate new UUID v4 for this request
			requestID = uuid.New().String()
		}

		// Add request ID to context for use in handlers
		ctx := context.WithValue(r.Context(), requestIDContextKey, requestID)
		r = r.WithContext(ctx)

		// Add request ID to response headers for client-side correlation
		w.Header().Set(RequestIDHeader, requestID)

		next.ServeHTTP(w, r)
	})
}

// GetRequestID extracts the request ID from the context.
// Returns empty string if no request ID is found.
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(requestIDContextKey).(string); ok {
		return requestID
	}
	return ""
}

// Logging is a middleware that logs details about each incoming HTTP request.
// It records the request method, path, remote address, and the duration it took
// to process the request.
//
// Additionally, it includes a security check to detect and prevent potential
// token leaks in URL query parameters or Authorization headers. If an access token
// or bearer token is found in the URL, it logs an error and returns a 403 Forbidden
// response to prevent sensitive information from being exposed in logs or browser history.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		w.Header().Set("Content-Type", "application/json")

		if strings.Contains(r.URL.RawQuery, "access_token=") ||
			strings.Contains(r.URL.RawQuery, bearerPrefix) {
			slog.Error("🚨 TOKEN LEAK DETECTED", "url", r.URL.String(), "ip", r.RemoteAddr)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)

		// Include request ID in logs for correlation
		requestID := GetRequestID(r.Context())
		slog.Info("request",
			"request_id", requestID,
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"duration", time.Since(start),
		)
	})
}

// MetricsMiddleware tracks HTTP request metrics (count, duration, active connections).
// This middleware should be applied early in the chain to capture all requests.
func (m *Middleware) MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Track active connections
		m.metrics.IncrementActiveConnections()
		defer m.metrics.DecrementActiveConnections()

		// Wrap response writer to capture status code
		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK, // Default to 200 if WriteHeader is never called
		}

		// Process request
		next.ServeHTTP(rw, r)

		// Record metrics
		duration := time.Since(start)
		m.metrics.RecordHTTPRequest(r.Method, r.URL.Path, rw.statusCode)
		m.metrics.RecordHTTPDuration(r.Method, r.URL.Path, duration)
	})
}

// Timeout adds request timeout to prevent long-running requests / Ajoute un timeout aux requêtes
func Timeout(duration time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), duration)
			defer cancel()

			// Replace request context with timeout context / Remplace le contexte avec timeout
			r = r.WithContext(ctx)

			// Channel to signal handler completion / Canal pour signaler la fin
			done := make(chan struct{})
			go func() {
				next.ServeHTTP(w, r)
				close(done)
			}()

			select {
			case <-done:
				// Request completed successfully / Requête terminée avec succès
				return
			case <-ctx.Done():
				// Timeout exceeded / Timeout dépassé
				if ctx.Err() == context.DeadlineExceeded {
					slog.Warn("request timeout", "path", r.URL.Path, "timeout", duration)
					http.Error(w, `{"error":"request timeout"}`, http.StatusGatewayTimeout)
				}
			}
		})
	}
}

// Middleware struct holds configuration and rate limiters for various middleware functions.
// It acts as a container for all the middleware-related dependencies and logic.
type Middleware struct {
	conf          *config.Config // Application configuration.
	globalLimiter *RateLimiter   // Global rate limiter applied to all requests.
	strictLimiter *RateLimiter   // Stricter rate limiter for sensitive endpoints (e.g., authentication).
	userLimiter   *RateLimiter   // Rate limiter applied per authenticated user.
	resendLimiter *RateLimiter
	metrics       *metrics.Metrics     // Prometheus metrics collectors.
	userRepo      ports.UserRepository // User repository for permission checks.
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code before writing it.
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// NewMiddleware creates a new instance of Middleware with the configured rate limiters.
// It initializes different rate limiters based on the application's configuration,
// allowing for flexible and granular control over request rates.
//
// The rate limiters are only initialized if `conf.RateLimiter.Enabled` is true.
//   - `globalLimiter`: Applies a general rate limit based on `conf.RateLimiter.RPS` and `Burst`.
//   - `strictLimiter`: For production environments, this limiter applies stricter limits (half of global)
//     to sensitive authentication endpoints to mitigate brute-force attacks.
//   - `userLimiter`: A more permissive rate limiter (twice the global limits) applied per authenticated user.
func NewMiddleware(conf *config.Config, metrics *metrics.Metrics, userRepo ports.UserRepository) *Middleware {
	mw := &Middleware{
		conf:     conf,
		metrics:  metrics,
		userRepo: userRepo,
	}

	// Initialize rate limiters only if enabled
	if conf.RateLimiter.Enabled {
		// Create a background context for rate limiter cleanup goroutines
		// This allows for graceful shutdown if needed in the future
		ctx := context.Background()

		// 1. Global rate limiter (based on config)
		mw.globalLimiter = NewRateLimiter(
			ctx,
			conf.RateLimiter.RPS,
			conf.RateLimiter.Burst,
		)

		// 2. Strict rate limiter for sensitive endpoints (auth)
		strictRPS := conf.RateLimiter.RPS
		strictBurst := conf.RateLimiter.Burst

		// In production, we divide the limits for auth by 2
		if conf.IsProduction() {
			strictRPS = strictRPS / 2
			if strictBurst > 2 {
				strictBurst = strictBurst / 2
			}
		}
		mw.strictLimiter = NewRateLimiter(ctx, strictRPS, strictBurst)

		// 3. Rate limiter per user (2x more permissive)
		userRPS := conf.RateLimiter.RPS * 2
		userBurst := conf.RateLimiter.Burst * 2
		mw.userLimiter = NewRateLimiter(ctx, userRPS, userBurst)

		// 4. Very strict rate limiter for resend verification (0.3 RPS = ~1 every 3 seconds, burst 3)
		// This prevents abuse of the email sending endpoint
		mw.resendLimiter = NewRateLimiter(ctx, 0.3, 3)
	}

	return mw
}

// Auth is a middleware that handles user authentication by validating JWT access tokens.
// It attempts to retrieve the token from either an "access_token" HTTP-only cookie
// or the "Authorization: Bearer" header.
//
// If a token is found, it is validated using the configured JWT secret.
// On successful validation, the JWT claims (containing user information) are extracted
// and stored in the request context under `ClaimsContextKey`. This makes user data
// easily accessible to subsequent handlers in the request chain.
//
// If no valid token is found or validation fails, it returns a 401 Unauthorized response.
func (m *Middleware) Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		var tokenStr string

		// Attempt to retrieve the token from the cookie
		if cookie, err := r.Cookie("access_token"); err == nil {
			tokenStr = cookie.Value
		} else {
			// Otherwise try the Authorization Bearer header
			authorization := r.Header.Get("Authorization")
			if !strings.HasPrefix(authorization, bearerPrefix) {
				ErrorResponse(w, `{"error":"forbidden"}`, http.StatusUnauthorized)
				return
			}
			tokenStr = strings.TrimPrefix(authorization, bearerPrefix)
		}

		claims, err := auth.ValidateJWT(tokenStr, m.conf.Auth.JWTSecret)
		if err != nil {
			m.metrics.RecordInvalidToken()
			ErrorResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Parse user ID from Subject field
		userID, err := strconv.ParseInt(claims.Subject, 10, 64)
		if err != nil {
			slog.Error("Failed to parse user ID from token", "subject", claims.Subject, "error", err)
			ErrorResponse(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Add both claims and userID to context
		ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
		ctx = context.WithValue(ctx, "userID", userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole is a middleware factory that creates role-based authorization middleware.
// It checks if the authenticated user has at least one of the specified roles.
// This middleware MUST be used after the Auth middleware, as it depends on the JWT claims
// being present in the request context.
//
// The role check supports a hierarchical model where higher-level roles automatically
// have access to lower-level protected resources:
// - admin > moderator > user
//
// For example, if you RequireRole("moderator"), an admin user will also have access.
//
// Parameters:
//   - requiredRole: The minimum role required to access the protected resource.
//
// Returns:
//   - A middleware function that checks the user's role before allowing access.
//   - If the user doesn't have the required role, it returns 403 Forbidden.
//   - If no auth claims are found (Auth middleware not applied), it returns 401 Unauthorized.
//
// Example usage:
//
//	// Protect an admin-only endpoint
//	mux.Handle("DELETE /api/users/{id}", chain(h.DeleteUser, mw, mw.Auth, mw.RequireRole(domain.RoleAdmin)))
//
//	// Protect a moderator endpoint (admin also has access)
//	mux.Handle("POST /api/moderate", chain(h.ModerateContent, mw, mw.Auth, mw.RequireRole(domain.RoleModerator)))
func (m *Middleware) RequireRole(requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract claims from context (should have been set by Auth middleware)
			claims, ok := r.Context().Value(ClaimsContextKey).(*auth.CustomClaims)
			if !ok {
				ErrorResponse(w, "Unauthorized: authentication required", http.StatusUnauthorized)
				return
			}

			// Get user's role from JWT claims
			userRole := claims.Role

			// Check if user has the minimum required role
			if !hasMinimumRole(userRole, requiredRole) {
				ErrorResponse(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			// User has sufficient permissions, continue
			next.ServeHTTP(w, r)
		})
	}
}

// hasMinimumRole checks if the user's role meets or exceeds the required role level.
// Role hierarchy: admin (3) > moderator (2) > user (1)
func hasMinimumRole(userRole, requiredRole string) bool {
	roleHierarchy := map[string]int{
		"user":      1,
		"moderator": 2,
		"admin":     3,
	}

	userLevel := roleHierarchy[userRole]
	requiredLevel := roleHierarchy[requiredRole]

	return userLevel >= requiredLevel
}

// Cors is a middleware that handles Cross-Origin Resource Sharing (CORS) for the application.
// It configures appropriate CORS headers based on the `AllowedOrigins` specified in the application's configuration.
//
// Key functionalities:
//  1. Sets `Access-Control-Allow-Origin` header to match the `Origin` of the incoming request
//     if it's in the list of allowed origins or if "*" is allowed.
//  2. Sets `Access-Control-Allow-Methods` to permit common HTTP methods (GET, POST, PUT, DELETE, OPTIONS).
//  3. Sets `Access-Control-Allow-Headers` to allow `Authorization`, `Content-Type`, and `X-CSRF-Token` headers.
//     The X-CSRF-Token header is required for CSRF protection (double-submit cookie pattern).
//  4. Sets `Access-Control-Allow-Credentials` to "true" to allow cookies and HTTP authentication
//     credentials to be sent with cross-origin requests.
//  5. For preflight OPTIONS requests, it immediately responds with a 200 OK status after setting headers.
func (m *Middleware) Cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		for _, allowed := range m.conf.Cors.AllowedOrigins {
			if allowed == "*" || allowed == origin {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				break
			}
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		// IMPORTANT: X-CSRF-Token must be in allowed headers for the double-submit cookie pattern to work
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-CSRF-Token")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders is a middleware that adds various HTTP security headers to responses.
// These headers help protect clients against common web vulnerabilities such as
// XSS, clickjacking, MIME-type sniffing, and ensure secure transport.
//
// The headers added include:
// - `X-Content-Type-Options: nosniff`: Prevents browsers from MIME-sniffing a response away from the declared content-type.
// - `X-Frame-Options: DENY`: Prevents clickjacking by disallowing the page from being rendered in a frame.
// - `X-XSS-Protection: 1; mode=block`: Enables the XSS filter in modern web browsers.
// - `Referrer-Policy: strict-origin-when-cross-origin`: Controls how much referrer information is included with requests.
// - `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`: Mitigates XSS and data injection attacks.
// - `Strict-Transport-Security`: (Only in production) Enforces secure (HTTPS) connections for a specified duration.
func (m *Middleware) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")

		if m.conf.IsProd() {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

// CSRF is a middleware that provides protection against Cross-Site Request Forgery (CSRF) attacks.
// It implements the "Double Submit Cookie" pattern, which involves comparing a token
// sent in an HTTP-only cookie with a token sent in a custom HTTP header.
//
// The middleware performs the following checks:
//  1. Retrieves the CSRF token from the "csrf_token" cookie.
//  2. Retrieves the CSRF token from the "X-CSRF-Token" HTTP header.
//  3. Compares the two tokens. If they do not match, or if either is missing,
//     it logs a warning and returns a 403 Forbidden response.
//
// This protection is typically applied to state-changing HTTP methods (e.g., POST, PUT, DELETE).
// Safe methods (GET, HEAD, OPTIONS, TRACE) are usually excluded from CSRF checks.
func (m *Middleware) CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("csrf_token")
		if err != nil {
			slog.Warn("CSRF middleware: missing csrf_token cookie", "err", err)
			ErrorResponse(w, "Forbidden", http.StatusForbidden)
			return
		}
		cookieToken := cookie.Value

		headerToken := r.Header.Get("X-CSRF-Token")

		if cookieToken == "" || headerToken == "" || cookieToken != headerToken {
			m.metrics.RecordCSRFFailure()
			slog.Warn("CSRF token mismatch", "cookie_len", len(cookieToken), "header_len", len(headerToken))
			ErrorResponse(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RequirePermission is a middleware that enforces granular permission-based access control.
// It checks if the authenticated user has the specified permission before allowing access
// to the protected resource.
//
// This middleware must be used AFTER the Auth middleware, as it depends on the user ID
// being present in the request context.
//
// Usage:
//
//	mux.Handle("/api/admin/users", chain(h.ListUsers, mw, mw.Auth, mw.RequirePermission(domain.PermissionUsersList)))
//
// Parameters:
//   - permission: The permission required to access the endpoint (e.g., domain.PermissionUsersRead)
//
// Returns:
//   - A middleware function that wraps the next handler with permission checking
//
// If the user doesn't have the required permission:
//   - Status: 403 Forbidden
//   - Response: {"error": "insufficient permissions"}
//   - Metrics: Records permission denial
func (m *Middleware) RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get user ID from context (set by Auth middleware)
			userIDVal := r.Context().Value("userID")
			if userIDVal == nil {
				slog.Error("RequirePermission: userID not found in context - Auth middleware not applied?")
				ErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			userID, ok := userIDVal.(int64)
			if !ok {
				slog.Error("RequirePermission: userID in context is not int64")
				ErrorResponse(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			// Check if user has the required permission
			hasPermission, err := m.userRepo.UserHasPermission(r.Context(), userID, domain.Permission(permission))
			if err != nil {
				slog.Error("RequirePermission: failed to check user permission",
					"user_id", userID,
					"permission", permission,
					"error", err,
				)
				ErrorResponse(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			if !hasPermission {
				// Record security metric
				m.metrics.RecordPermissionDenial(permission)

				slog.Warn("Permission denied",
					"user_id", userID,
					"permission", permission,
					"path", r.URL.Path,
					"method", r.Method,
				)

				ErrorResponse(w, "Insufficient permissions", http.StatusForbidden)
				return
			}

			// User has permission, proceed to next handler
			slog.Debug("Permission granted",
				"user_id", userID,
				"permission", permission,
				"path", r.URL.Path,
			)

			next.ServeHTTP(w, r)
		})
	}
}
