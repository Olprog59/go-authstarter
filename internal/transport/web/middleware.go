package web

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Olprog59/go-authstarter/internal/config"
	"github.com/Olprog59/go-authstarter/internal/domain"
	"github.com/Olprog59/go-authstarter/internal/metrics"
	"github.com/Olprog59/go-authstarter/internal/ports"
	"github.com/Olprog59/go-authstarter/internal/service/auth"
	"github.com/google/uuid"
)

const (
	bearerPrefix    = "Bearer "
	RequestIDKey    = "request_id"
	RequestIDHeader = "X-Request-ID"
)

type contextKey string

const requestIDContextKey contextKey = "request_id"

// RequestID generates unique request ID / Génère un ID unique pour la requête
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get(RequestIDHeader)
		if requestID == "" {
			requestID = uuid.New().String()
		}

		ctx := context.WithValue(r.Context(), requestIDContextKey, requestID)
		r = r.WithContext(ctx)

		w.Header().Set(RequestIDHeader, requestID)

		// Add request ID to logger context for tracing
		logger := slog.With("request_id", requestID)
		ctx = context.WithValue(ctx, "logger", logger)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// GetRequestID extracts request ID from context / Extrait l'ID de la requête du contexte
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(requestIDContextKey).(string); ok {
		return requestID
	}
	return ""
}



// Logging logs HTTP requests and prevents token leaks / Enregistre les requêtes et prévient les fuites
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

// MetricsMiddleware tracks HTTP request metrics / Suit les métriques des requêtes HTTP
func (m *Middleware) MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		m.metrics.IncrementActiveConnections()
		defer m.metrics.DecrementActiveConnections()

		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		m.metrics.RecordHTTPRequest(r.Method, r.URL.Path, rw.statusCode)
		m.metrics.RecordHTTPDuration(r.Method, r.URL.Path, duration)
	})
}

// Timeout adds request timeout / Ajoute un timeout aux requêtes
func Timeout(duration time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), duration)
			defer cancel()

			r = r.WithContext(ctx)

			done := make(chan struct{})
			go func() {
				next.ServeHTTP(w, r)
				close(done)
			}()

			select {
			case <-done:
				return
			case <-ctx.Done():
				if ctx.Err() == context.DeadlineExceeded {
					slog.Warn("request timeout", "path", r.URL.Path, "timeout", duration)
					http.Error(w, `{"error":"request timeout"}`, http.StatusGatewayTimeout)
				}
			}
		})
	}
}

// Middleware holds middleware configuration and dependencies / Contient la configuration middleware
type Middleware struct {
	conf          *config.Config
	globalLimiter *RateLimiter
	strictLimiter *RateLimiter
	userLimiter   *RateLimiter
	resendLimiter *RateLimiter
	metrics       *metrics.Metrics
	userRepo      ports.UserRepository
}

// responseWriter wraps ResponseWriter to capture status / Encapsule ResponseWriter pour capturer le statut
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures status code / Capture le code de statut
func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// NewMiddleware creates middleware with rate limiters / Crée le middleware avec limiteurs
func NewMiddleware(conf *config.Config, metrics *metrics.Metrics, userRepo ports.UserRepository) *Middleware {
	mw := &Middleware{
		conf:     conf,
		metrics:  metrics,
		userRepo: userRepo,
	}

	if conf.RateLimiter.Enabled {
		ctx := context.Background()

		mw.globalLimiter = NewRateLimiter(
			ctx,
			conf.RateLimiter.RPS,
			conf.RateLimiter.Burst,
		)

		strictRPS := conf.RateLimiter.RPS
		strictBurst := conf.RateLimiter.Burst

		if conf.IsProduction() {
			strictRPS = strictRPS / 2
			if strictBurst > 2 {
				strictBurst = strictBurst / 2
			}
		}
		mw.strictLimiter = NewRateLimiter(ctx, strictRPS, strictBurst)

		userRPS := conf.RateLimiter.RPS * 2
		userBurst := conf.RateLimiter.Burst * 2
		mw.userLimiter = NewRateLimiter(ctx, userRPS, userBurst)

		mw.resendLimiter = NewRateLimiter(ctx, 0.3, 3)
	}

	return mw
}

// Auth validates JWT tokens / Valide les tokens JWT
func (m *Middleware) Auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		var tokenStr string

		if cookie, err := r.Cookie("access_token"); err == nil {
			tokenStr = cookie.Value
		} else {
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

		userID, err := strconv.ParseInt(claims.Subject, 10, 64)
		if err != nil {
			slog.Error("Failed to parse user ID from token", "subject", claims.Subject, "error", err)
			ErrorResponse(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
		ctx = context.WithValue(ctx, "userID", userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole checks user role with hierarchy / Vérifie le rôle avec hiérarchie
func (m *Middleware) RequireRole(requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(ClaimsContextKey).(*auth.CustomClaims)
			if !ok {
				ErrorResponse(w, "Unauthorized: authentication required", http.StatusUnauthorized)
				return
			}

			userRole := claims.Role

			if !hasMinimumRole(userRole, requiredRole) {
				ErrorResponse(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// hasMinimumRole checks role hierarchy / Vérifie la hiérarchie des rôles
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

// Cors handles CORS headers / Gère les en-têtes CORS
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
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-CSRF-Token")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// SecurityHeaders adds security headers / Ajoute les en-têtes de sécurité
func (m *Middleware) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Content Security Policy - Restrict sources to self and trusted CDNs
		// Allow inline scripts/styles for development, restrict in production
		cspValue := "default-src 'self'; frame-ancestors 'none'; object-src 'none'"
		if m.conf.IsProd() {
			cspValue += "; script-src 'self' cdn.jsdelivr.net; style-src 'self' cdn.jsdelivr.net"
		} else {
			cspValue += "; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net"
		}
		cspValue += "; img-src 'self' data:; font-src 'self'; connect-src 'self'"
		w.Header().Set("Content-Security-Policy", cspValue)

		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// Prevent XSS attacks
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Referrer Policy - Only send referrer to same origin
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions Policy - Restrict browser features
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")

		// Strict Transport Security - Enforce HTTPS (only in production)
		if m.conf.IsProd() {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		}

		next.ServeHTTP(w, r)
	})
}

// CSRF protects against CSRF attacks / Protège contre les attaques CSRF
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

// RequirePermission checks user permission / Vérifie la permission de l'utilisateur
func (m *Middleware) RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

			next.ServeHTTP(w, r)
		})
	}
}
