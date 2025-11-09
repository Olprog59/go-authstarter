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

const (
	bearerPrefix = "Bearer " // Standard prefix for Bearer tokens in Authorization headers.
)

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

		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"duration", time.Since(start),
		)
	})
}

// Middleware struct holds configuration and rate limiters for various middleware functions.
// It acts as a container for all the middleware-related dependencies and logic.
type Middleware struct {
	conf          *config.Config // Application configuration.
	globalLimiter *RateLimiter   // Global rate limiter applied to all requests.
	strictLimiter *RateLimiter   // Stricter rate limiter for sensitive endpoints (e.g., authentication).
	userLimiter   *RateLimiter   // Rate limiter applied per authenticated user.
}

// NewMiddleware creates a new instance of Middleware with the configured rate limiters.
// It initializes different rate limiters based on the application's configuration,
// allowing for flexible and granular control over request rates.
//
// The rate limiters are only initialized if `conf.RateLimiter.Enabled` is true.
// - `globalLimiter`: Applies a general rate limit based on `conf.RateLimiter.RPS` and `Burst`.
// - `strictLimiter`: For production environments, this limiter applies stricter limits (half of global)
//   to sensitive authentication endpoints to mitigate brute-force attacks.
// - `userLimiter`: A more permissive rate limiter (twice the global limits) applied per authenticated user.
func NewMiddleware(conf *config.Config) *Middleware {
	mw := &Middleware{
		conf: conf,
	}

	// Initialize rate limiters only if enabled
	if conf.RateLimiter.Enabled {
		// 1. Global rate limiter (based on config)
		mw.globalLimiter = NewRateLimiter(
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
		mw.strictLimiter = NewRateLimiter(strictRPS, strictBurst)

		// 3. Rate limiter per user (2x more permissive)
		userRPS := conf.RateLimiter.RPS * 2
		userBurst := conf.RateLimiter.Burst * 2
		mw.userLimiter = NewRateLimiter(userRPS, userBurst)
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
			ErrorResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Cors is a middleware that handles Cross-Origin Resource Sharing (CORS) for the application.
// It configures appropriate CORS headers based on the `AllowedOrigins` specified in the application's configuration.
//
// Key functionalities:
// 1.  Sets `Access-Control-Allow-Origin` header to match the `Origin` of the incoming request
//     if it's in the list of allowed origins or if "*" is allowed.
// 2.  Sets `Access-Control-Allow-Methods` to permit common HTTP methods (GET, POST, PUT, DELETE, OPTIONS).
// 3.  Sets `Access-Control-Allow-Headers` to allow `Authorization` and `Content-Type` headers.
// 4.  Sets `Access-Control-Allow-Credentials` to "true" to allow cookies and HTTP authentication
//     credentials to be sent with cross-origin requests.
// 5.  For preflight OPTIONS requests, it immediately responds with a 200 OK status after setting headers.
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
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
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
// 1.  Retrieves the CSRF token from the "csrf_token" cookie.
// 2.  Retrieves the CSRF token from the "X-CSRF-Token" HTTP header.
// 3.  Compares the two tokens. If they do not match, or if either is missing,
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
			slog.Warn("CSRF token mismatch", "cookie_len", len(cookieToken), "header_len", len(headerToken))
			ErrorResponse(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
