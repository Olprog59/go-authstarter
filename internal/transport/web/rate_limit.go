package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter manages rate limiters for visitors based on their IP address or user ID.
// It uses a map to store a `Visitor` object for each unique identifier.
type RateLimiter struct {
	visitors map[string]*Visitor // Map of visitors, keyed by a unique identifier (e.g., IP hash or user ID).
	mu       sync.RWMutex        // Read-write mutex to protect concurrent access to the visitors map.
	rate     rate.Limit          // The number of requests allowed per second.
	burst    int                 // The maximum burst of requests allowed.
	ctx      context.Context     // Context for graceful shutdown of cleanup goroutine.
	cancel   context.CancelFunc  // Cancel function to stop cleanup goroutine.
}

// Visitor represents a single visitor (e.g., an IP address or user) and their associated rate limiter.
type Visitor struct {
	limiter  *rate.Limiter // The actual rate limiter for this visitor.
	lastSeen time.Time     // The last time this visitor made a request.
}

// NewRateLimiter creates and returns a new RateLimiter.
// It initializes the visitors map and starts a background goroutine to clean up
// inactive visitors periodically.
//
// Parameters:
//   - ctx: Context for graceful shutdown of the cleanup goroutine.
//   - rps: Requests per second allowed for each visitor.
//   - burst: The maximum burst of requests allowed.
func NewRateLimiter(ctx context.Context, rps float64, burst int) *RateLimiter {
	cleanupCtx, cancel := context.WithCancel(ctx)

	rl := &RateLimiter{
		visitors: make(map[string]*Visitor),
		rate:     rate.Limit(rps),
		burst:    burst,
		ctx:      cleanupCtx,
		cancel:   cancel,
	}

	go rl.cleanupVisitors()

	return rl
}

// Stop gracefully stops the rate limiter's cleanup goroutine.
// Should be called during application shutdown.
func (rl *RateLimiter) Stop() {
	rl.cancel()
}

// getVisitor retrieves or creates a rate limiter for a given identifier (e.g., IP hash).
// If a visitor does not exist in the map, a new one is created with a new rate limiter.
// The `lastSeen` time for the visitor is updated on each call.
func (rl *RateLimiter) getVisitor(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists {
		limiter := rate.NewLimiter(rl.rate, rl.burst)
		rl.visitors[ip] = &Visitor{
			limiter:  limiter,
			lastSeen: time.Now(),
		}
		return limiter
	}

	v.lastSeen = time.Now()
	return v.limiter
}

// cleanupVisitors is a background task that runs in a goroutine to periodically
// remove inactive visitors from the map. This prevents the map from growing
// indefinitely and consuming too much memory. A visitor is considered inactive
// if they haven't been seen for more than 3 minutes.
//
// The goroutine respects context cancellation for graceful shutdown.
func (rl *RateLimiter) cleanupVisitors() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Perform cleanup
			rl.mu.Lock()
			for ip, v := range rl.visitors {
				if time.Since(v.lastSeen) > 3*time.Minute {
					delete(rl.visitors, ip)
				}
			}
			rl.mu.Unlock()

		case <-rl.ctx.Done():
			// Context cancelled - graceful shutdown
			return
		}
	}
}

// getIP extracts the real client IP address from the request.
// It checks common headers used by reverse proxies (`X-Forwarded-For`, `X-Real-IP`)
// before falling back to the `RemoteAddr` field of the request.
//
// IMPORTANT: X-Forwarded-For format is: "client, proxy1, proxy2"
// We take the FIRST IP (client) as it's the original requester.
// getIP extracts client IP address / Extrait l'adresse IP du client
func getIP(r *http.Request) string {
	return getIPWithTrustedProxies(r, nil)
}

// getIPWithTrustedProxies extracts the client IP with trusted proxy validation.
// If trustedProxies is provided and not empty, it validates that the RemoteAddr
// is in the trusted list before trusting X-Forwarded-For or X-Real-IP headers.
func getIPWithTrustedProxies(r *http.Request, trustedProxies []string) string {
	// Extract the immediate connection IP (RemoteAddr)
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If SplitHostPort fails, it might be just an IP without port
		remoteIP = r.RemoteAddr
	}

	// If no trusted proxies configured, only use RemoteAddr (secure default)
	if len(trustedProxies) == 0 {
		return remoteIP
	}

	// Check if the request is from a trusted proxy
	isTrustedProxy := false
	for _, trustedIP := range trustedProxies {
		if remoteIP == trustedIP {
			isTrustedProxy = true
			break
		}
	}

	// If not from a trusted proxy, use RemoteAddr (cannot be spoofed)
	if !isTrustedProxy {
		return remoteIP
	}

	// Request is from a trusted proxy - check proxy headers
	// Check for the X-Forwarded-For header, which contains a comma-separated list of IPs.
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Split by comma to get individual IPs
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			// Take the first IP (the original client) and trim whitespace
			clientIP := strings.TrimSpace(ips[0])
			// Validate it's a proper IP address
			if net.ParseIP(clientIP) != nil {
				return clientIP
			}
		}
	}

	// Check for the X-Real-IP header (used by some proxies like nginx)
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		realIP = strings.TrimSpace(realIP)
		if net.ParseIP(realIP) != nil {
			return realIP
		}
	}

	// Fallback to RemoteAddr if headers are invalid
	return remoteIP
}

// hashIP creates a SHA-256 hash of an IP address to avoid storing raw IP addresses.
// This is a privacy-enhancing measure.
func hashIP(ip string) string {
	h := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(h[:])
}

// RateLimit is a middleware that applies a global rate limit to all incoming requests.
// It uses the client's IP address as the identifier for rate limiting.
// If the rate limiter is disabled in the configuration, the middleware does nothing.
func (mw *Middleware) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bypass if the rate limiter is disabled.
		if !mw.conf.RateLimiter.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		ip := getIPWithTrustedProxies(r, mw.conf.Security.TrustedProxies)
		ipHash := hashIP(ip)

		// Check if the request is allowed by the global rate limiter.
		if !mw.globalLimiter.getVisitor(ipHash).Allow() {
			mw.metrics.RecordRateLimitHit("global")
			sendRateLimitErrorAdvanced(w, "Too many requests. Please try again later.", 60)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RateLimitStrict is a middleware that applies a stricter rate limit, typically
// used for sensitive endpoints like authentication (login, register).
// It uses a separate, more restrictive rate limiter (`strictLimiter`).
func (mw *Middleware) RateLimitStrict(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !mw.conf.RateLimiter.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		ip := getIPWithTrustedProxies(r, mw.conf.Security.TrustedProxies)
		ipHash := hashIP(ip)

		// Check if the request is allowed by the strict rate limiter.
		if !mw.strictLimiter.getVisitor(ipHash).Allow() {
			mw.metrics.RecordRateLimitHit("strict")
			sendRateLimitErrorAdvanced(w, "Too many requests. Please try again later.", 60)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RateLimitByUser applies rate limit per user / Applique une limite de taux par utilisateur
func (mw *Middleware) RateLimitByUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !mw.conf.RateLimiter.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Try to get the user ID from the context.
		userID, ok := r.Context().Value("userID").(int64)
		if !ok {
			// If the user is not authenticated, fall back to IP-based rate limiting.
			ip := getIPWithTrustedProxies(r, mw.conf.Security.TrustedProxies)
			ipHash := hashIP(ip)

			if !mw.userLimiter.getVisitor(ipHash).Allow() {
				mw.metrics.RecordRateLimitHit("user_ip")
				sendRateLimitErrorAdvanced(w, "Too many requests. Please try again later.", 60)
				return
			}
		} else {
			// If the user is authenticated, use their user ID as the key.
			userKey := fmt.Sprintf("user_%d", userID)
			if !mw.userLimiter.getVisitor(userKey).Allow() {
				mw.metrics.RecordRateLimitHit("user_authenticated")
				sendRateLimitErrorAdvanced(w, "Too many requests. Please try again later.", 60)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// RateLimitErrorResponse defines a structured response for rate limiting errors.
// It provides more context to the client than a simple error message.
type RateLimitErrorResponse struct {
	Error      string    `json:"error"`               // A machine-readable error code.
	Message    string    `json:"message"`             // A human-readable error message.
	Code       int       `json:"code"`                // The HTTP status code.
	RetryAfter int       `json:"retry_after_seconds"` // Suggested time to wait before retrying, in seconds.
	Timestamp  time.Time `json:"timestamp"`           // The timestamp of when the error occurred.
}

// sendRateLimitErrorAdvanced sends a detailed JSON response when a rate limit is exceeded.
// It sets the HTTP status to 429 Too Many Requests and includes a structured JSON body
// with details about the error and a suggested retry time.
func sendRateLimitErrorAdvanced(w http.ResponseWriter, message string, retryAfter int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-RateLimit-Retry-After", fmt.Sprintf("%d", retryAfter))
	w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
	w.WriteHeader(http.StatusTooManyRequests)

	response := RateLimitErrorResponse{
		Error:      "rate_limit_exceeded",
		Message:    message,
		Code:       http.StatusTooManyRequests,
		RetryAfter: retryAfter,
		Timestamp:  time.Now().UTC(),
	}

	json.NewEncoder(w).Encode(response)
}

// RateLimitHeaders represents the standard rate limit headers included in API responses.
// This provides clients with information about their current rate limit status.
type RateLimitHeaders struct {
	Limit     int `json:"limit"`     // The total number of requests allowed in the current window.
	Remaining int `json:"remaining"` // The number of requests remaining in the current window.
	Reset     int `json:"reset"`     // The timestamp (in epoch seconds) when the rate limit window resets.
}

// addRateLimitHeaders adds informative rate limit headers to the HTTP response,
// similar to the headers used by the GitHub API.
func addRateLimitHeaders(w http.ResponseWriter, limit, remaining, resetTime int) {
	w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
	w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
	w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime))
}

func (mw *Middleware) RateLimitResend(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !mw.conf.RateLimiter.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		ip := getIPWithTrustedProxies(r, mw.conf.Security.TrustedProxies)
		ipHash := hashIP(ip)

		if !mw.resendLimiter.getVisitor(ipHash).Allow() {
			sendRateLimitErrorAdvanced(w, "You can only resend verification emails 3 times per 10 seconds. Please wait.", 10)
			return
		}

		next.ServeHTTP(w, r)
	})
}
