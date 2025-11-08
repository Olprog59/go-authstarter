package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter structure pour gérer les limiteurs par IP
type RateLimiter struct {
	visitors map[string]*Visitor
	mu       sync.RWMutex
	rate     rate.Limit // requêtes par seconde
	burst    int        // capacité du bucket
}

// Visitor représente un visiteur avec son limiteur
type Visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter crée un nouveau rate limiter
// rps = requêtes par seconde, burst = nombre de requêtes simultanées autorisées
func NewRateLimiter(rps float64, burst int) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*Visitor),
		rate:     rate.Limit(rps),
		burst:    burst,
	}

	// Nettoyage automatique toutes les 5 minutes
	go rl.cleanupVisitors()

	return rl
}

// getVisitor récupère ou crée un visiteur pour une IP donnée
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

// cleanupVisitors supprime les visiteurs inactifs depuis plus de 3 minutes
func (rl *RateLimiter) cleanupVisitors() {
	for {
		time.Sleep(5 * time.Minute)

		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// getIP extrait l'IP réelle du client
func getIP(r *http.Request) string {
	// Vérifier X-Forwarded-For (proxy/load balancer)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Prendre la première IP (client original)
		if ip, _, err := net.SplitHostPort(forwarded); err == nil {
			return ip
		}
		return forwarded
	}

	// Vérifier X-Real-IP
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}

	// Utiliser RemoteAddr en dernier recours
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// hashIP crée un hash de l'IP pour éviter de stocker les IPs en clair
func hashIP(ip string) string {
	h := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(h[:])
}

// Middleware RateLimit pour votre application
func (mw *Middleware) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vérifier si le rate limiter est activé
		if !mw.conf.RateLimiter.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		ip := getIP(r)
		ipHash := hashIP(ip)

		if !mw.globalLimiter.getVisitor(ipHash).Allow() {
			sendRateLimitErrorAdvanced(w, "Too many requests. Please try again later.", 60)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RateLimitStrict - Version plus stricte pour les endpoints sensibles (auth)
func (mw *Middleware) RateLimitStrict(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !mw.conf.RateLimiter.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		ip := getIP(r)
		ipHash := hashIP(ip)

		if !mw.strictLimiter.getVisitor(ipHash).Allow() {
			sendRateLimitErrorAdvanced(w, "Too many requests. Please try again later.", 60)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RateLimitByUser - Rate limit par utilisateur authentifié
func (mw *Middleware) RateLimitByUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !mw.conf.RateLimiter.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Extraire l'ID utilisateur du contexte (après Auth middleware)
		userID, ok := r.Context().Value("userID").(int64)
		if !ok {
			// Si pas d'userID, utiliser l'IP
			ip := getIP(r)
			ipHash := hashIP(ip)

			if !mw.userLimiter.getVisitor(ipHash).Allow() {
				sendRateLimitErrorAdvanced(w, "Too many requests. Please try again later.", 60)
				return
			}
		} else {
			// Rate limit par user ID
			userKey := fmt.Sprintf("user_%d", userID)
			if !mw.userLimiter.getVisitor(userKey).Allow() {
				sendRateLimitErrorAdvanced(w, "Too many requests. Please try again later.", 60)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// RateLimitErrorResponse structure enrichie pour les erreurs de rate limiting
type RateLimitErrorResponse struct {
	Error      string    `json:"error"`
	Message    string    `json:"message"`
	Code       int       `json:"code"`
	RetryAfter int       `json:"retry_after_seconds"` // Temps d'attente suggéré
	Timestamp  time.Time `json:"timestamp"`
}

// sendRateLimitErrorAdvanced envoie une réponse JSON enrichie
func sendRateLimitErrorAdvanced(w http.ResponseWriter, message string, retryAfter int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-RateLimit-Retry-After", fmt.Sprintf("%d", retryAfter))
	w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter)) // Header HTTP standard
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

// Version avec tracking des limites (optionnel, pour afficher les quotas restants)
type RateLimitHeaders struct {
	Limit     int `json:"limit"`     // Nombre total de requêtes autorisées
	Remaining int `json:"remaining"` // Requêtes restantes
	Reset     int `json:"reset"`     // Timestamp de reset (epoch)
}

// addRateLimitHeaders ajoute des headers informatifs (comme GitHub API)
func addRateLimitHeaders(w http.ResponseWriter, limit, remaining, resetTime int) {
	w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
	w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
	w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetTime))
}
