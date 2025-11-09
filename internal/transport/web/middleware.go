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
	bearerPrefix = "Bearer "
)

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

type Middleware struct {
	conf          *config.Config
	globalLimiter *RateLimiter // Rate limiter global
	strictLimiter *RateLimiter // Rate limiter strict pour auth
	userLimiter   *RateLimiter // Rate limiter par utilisateur
}

// NewMiddleware crée une nouvelle instance de Middleware avec les rate limiters configurés
func NewMiddleware(conf *config.Config) *Middleware {
	mw := &Middleware{
		conf: conf,
	}

	if conf.RateLimiter.Enabled {

		mw.globalLimiter = NewRateLimiter(
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
		mw.strictLimiter = NewRateLimiter(strictRPS, strictBurst)

		userRPS := conf.RateLimiter.RPS * 2
		userBurst := conf.RateLimiter.Burst * 2
		mw.userLimiter = NewRateLimiter(userRPS, userBurst)
	}

	return mw
}

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
			ErrorResponse(w, err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

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

// CSRF est un middleware pour la protection contre les attaques CSRF via le pattern "Double Submit Cookie".
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
