package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus metric collectors / Contient tous les collecteurs de métriques Prometheus
type Metrics struct {
	// Authentication metrics
	LoginAttempts      *prometheus.CounterVec   // Total login attempts by status (success/failure/locked)
	RegistrationTotal  prometheus.Counter       // Total registration attempts
	EmailVerifications *prometheus.CounterVec   // Email verifications by status (success/failure)
	TokenRefreshes     *prometheus.CounterVec   // Token refresh operations by status
	AccountLockouts    prometheus.Counter       // Total account lockouts due to failed attempts

	// HTTP metrics
	HTTPRequestsTotal    *prometheus.CounterVec   // Total HTTP requests by method, path, status
	HTTPRequestDuration  *prometheus.HistogramVec // HTTP request latency in seconds
	ActiveConnections    prometheus.Gauge         // Current number of active HTTP connections

	// Security metrics
	RateLimitHits      *prometheus.CounterVec // Rate limit violations by endpoint
	CSRFFailures       prometheus.Counter     // CSRF validation failures
	InvalidTokens      prometheus.Counter     // Invalid/expired JWT token attempts
	TokenBindingFails  prometheus.Counter     // Token binding verification failures (IP/UA mismatch)
	PermissionDenials  *prometheus.CounterVec // Permission check failures by permission type

	// System metrics
	DatabaseConnections prometheus.Gauge     // Current database connection pool size
	BackgroundTasks     *prometheus.GaugeVec // Status of background tasks (running/stopped)
}

// NewMetrics initializes Metrics instance / Initialise une instance Metrics
func NewMetrics(reg prometheus.Registerer) *Metrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	factory := promauto.With(reg)

	m := &Metrics{
		// Authentication metrics
		LoginAttempts: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_login_attempts_total",
				Help: "Total number of login attempts by status (success, failure, locked, unverified)",
			},
			[]string{"status"},
		),

		RegistrationTotal: factory.NewCounter(
			prometheus.CounterOpts{
				Name: "auth_registrations_total",
				Help: "Total number of user registrations",
			},
		),

		EmailVerifications: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_email_verifications_total",
				Help: "Total number of email verification attempts by status",
			},
			[]string{"status"},
		),

		TokenRefreshes: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "auth_token_refreshes_total",
				Help: "Total number of token refresh operations by status",
			},
			[]string{"status"},
		),

		AccountLockouts: factory.NewCounter(
			prometheus.CounterOpts{
				Name: "auth_account_lockouts_total",
				Help: "Total number of account lockouts due to failed login attempts",
			},
		),

		// HTTP metrics
		HTTPRequestsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total number of HTTP requests by method, path, and status code",
			},
			[]string{"method", "path", "status_code"},
		),

		HTTPRequestDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: "http_request_duration_seconds",
				Help: "HTTP request latency in seconds",
				// Buckets optimized for API response times: 10ms to 10s
				Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			},
			[]string{"method", "path"},
		),

		ActiveConnections: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "http_active_connections",
				Help: "Current number of active HTTP connections",
			},
		),

		// Security metrics
		RateLimitHits: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "security_rate_limit_hits_total",
				Help: "Total number of rate limit violations by endpoint",
			},
			[]string{"endpoint"},
		),

		CSRFFailures: factory.NewCounter(
			prometheus.CounterOpts{
				Name: "security_csrf_failures_total",
				Help: "Total number of CSRF validation failures",
			},
		),

		InvalidTokens: factory.NewCounter(
			prometheus.CounterOpts{
				Name: "security_invalid_tokens_total",
				Help: "Total number of invalid or expired JWT token attempts",
			},
		),

		TokenBindingFails: factory.NewCounter(
			prometheus.CounterOpts{
				Name: "security_token_binding_failures_total",
				Help: "Total number of token binding verification failures (IP/UA mismatch)",
			},
		),

		PermissionDenials: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "security_permission_denials_total",
				Help: "Total number of permission check failures by permission type",
			},
			[]string{"permission"},
		),

		// System metrics
		DatabaseConnections: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "database_connections_active",
				Help: "Current number of active database connections",
			},
		),

		BackgroundTasks: factory.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "background_tasks_status",
				Help: "Status of background tasks (1=running, 0=stopped)",
			},
			[]string{"task_name"},
		),
	}

	return m
}

// RecordLoginAttempt records a login attempt with the given status.
// Status can be: "success", "failure", "locked", or "unverified"
func (m *Metrics) RecordLoginAttempt(status string) {
	m.LoginAttempts.WithLabelValues(status).Inc()
}

// RecordRegistration increments the registration counter.
func (m *Metrics) RecordRegistration() {
	m.RegistrationTotal.Inc()
}

// RecordEmailVerification records an email verification attempt.
// Status can be: "success" or "failure"
func (m *Metrics) RecordEmailVerification(status string) {
	m.EmailVerifications.WithLabelValues(status).Inc()
}

// RecordTokenRefresh records a token refresh operation.
// Status can be: "success", "invalid", "expired", or "binding_failure"
func (m *Metrics) RecordTokenRefresh(status string) {
	m.TokenRefreshes.WithLabelValues(status).Inc()
}

// RecordAccountLockout increments the account lockout counter.
func (m *Metrics) RecordAccountLockout() {
	m.AccountLockouts.Inc()
}

// RecordHTTPRequest records an HTTP request with method, path, and status code.
func (m *Metrics) RecordHTTPRequest(method, path string, statusCode int) {
	m.HTTPRequestsTotal.WithLabelValues(method, path, statusCodeToString(statusCode)).Inc()
}

// RecordHTTPDuration records the duration of an HTTP request.
func (m *Metrics) RecordHTTPDuration(method, path string, duration time.Duration) {
	m.HTTPRequestDuration.WithLabelValues(method, path).Observe(duration.Seconds())
}

// IncrementActiveConnections increments the active connections gauge.
func (m *Metrics) IncrementActiveConnections() {
	m.ActiveConnections.Inc()
}

// DecrementActiveConnections decrements the active connections gauge.
func (m *Metrics) DecrementActiveConnections() {
	m.ActiveConnections.Dec()
}

// RecordRateLimitHit records a rate limit violation for a specific endpoint.
func (m *Metrics) RecordRateLimitHit(endpoint string) {
	m.RateLimitHits.WithLabelValues(endpoint).Inc()
}

// RecordCSRFFailure increments the CSRF failure counter.
func (m *Metrics) RecordCSRFFailure() {
	m.CSRFFailures.Inc()
}

// RecordInvalidToken increments the invalid token counter.
func (m *Metrics) RecordInvalidToken() {
	m.InvalidTokens.Inc()
}

// RecordTokenBindingFailure increments the token binding failure counter.
func (m *Metrics) RecordTokenBindingFailure() {
	m.TokenBindingFails.Inc()
}

// UpdateDatabaseConnections updates the database connections gauge.
func (m *Metrics) UpdateDatabaseConnections(count int) {
	m.DatabaseConnections.Set(float64(count))
}

// SetBackgroundTaskStatus sets the status of a background task.
// Status: 1 for running, 0 for stopped.
func (m *Metrics) SetBackgroundTaskStatus(taskName string, running bool) {
	status := 0.0
	if running {
		status = 1.0
	}
	m.BackgroundTasks.WithLabelValues(taskName).Set(status)
}

// statusCodeToString converts HTTP status code to string / Convertit le code de statut HTTP en chaîne
func statusCodeToString(code int) string {
	// Common status codes as exact strings
	switch code {
	case 200:
		return "200"
	case 201:
		return "201"
	case 400:
		return "400"
	case 401:
		return "401"
	case 403:
		return "403"
	case 404:
		return "404"
	case 429:
		return "429"
	case 500:
		return "500"
	case 503:
		return "503"
	default:
		// Group others by range
		if code >= 200 && code < 300 {
			return "2xx"
		} else if code >= 300 && code < 400 {
			return "3xx"
		} else if code >= 400 && code < 500 {
			return "4xx"
		} else if code >= 500 && code < 600 {
			return "5xx"
		}
		return "unknown"
	}
}

// RecordPermissionDenial increments permission denial counter / Incrémente le compteur de refus de permission
func (m *Metrics) RecordPermissionDenial(permission string) {
	m.PermissionDenials.WithLabelValues(permission).Inc()
}
