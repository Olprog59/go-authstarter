package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"
)

// HealthResponse represents the response structure for health check endpoints.
type HealthResponse struct {
	Status    string            `json:"status"`              // "ok" or "error"
	Timestamp time.Time         `json:"timestamp"`           // Current server time
	Checks    map[string]string `json:"checks,omitempty"`    // Individual component health
	Version   string            `json:"version,omitempty"`   // Application version (optional)
	Uptime    string            `json:"uptime,omitempty"`    // Server uptime (optional)
}

var startTime = time.Now()

// HealthCheck handles the /health endpoint.
// This is a lightweight endpoint that always returns 200 OK if the service is running.
// It's primarily used by load balancers and monitoring systems to check if the service is alive.
//
// Response includes:
// - status: Always "ok" if this handler executes
// - timestamp: Current server time
// - uptime: How long the service has been running
//
// This endpoint does NOT check dependencies (database, external services).
// Use /readiness for dependency checks.
func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(startTime)

	response := HealthResponse{
		Status:    "ok",
		Timestamp: time.Now().UTC(),
		Uptime:    formatUptime(uptime),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// ReadinessCheck handles the /readiness endpoint.
// This endpoint checks if the service is ready to accept traffic by verifying
// that all critical dependencies (database, external services) are available.
//
// Use cases:
// - Kubernetes readiness probes
// - Load balancer health checks
// - Deployment health validation
//
// Response includes:
// - status: "ok" if all checks pass, "error" if any check fails
// - checks: Map of component statuses (e.g., {"database": "ok"})
// - timestamp: Current server time
//
// Returns:
// - 200 OK if all dependencies are healthy
// - 503 Service Unavailable if any dependency is unhealthy
func (h *Handler) ReadinessCheck(w http.ResponseWriter, r *http.Request) {
	checks := make(map[string]string)
	allHealthy := true

	// Check database connectivity
	dbStatus := h.checkDatabase()
	checks["database"] = dbStatus
	if dbStatus != "ok" {
		allHealthy = false
	}

	// You can add more checks here:
	// checks["redis"] = h.checkRedis()
	// checks["smtp"] = h.checkSMTP()
	// checks["external_api"] = h.checkExternalAPI()

	status := "ok"
	httpStatus := http.StatusOK

	if !allHealthy {
		status = "error"
		httpStatus = http.StatusServiceUnavailable
	}

	response := HealthResponse{
		Status:    status,
		Timestamp: time.Now().UTC(),
		Checks:    checks,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(response)
}

// checkDatabase verifies database connectivity by executing a simple ping.
// Returns "ok" if database is reachable, "error" otherwise.
func (h *Handler) checkDatabase() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := h.container.DB.PingContext(ctx); err != nil {
		return "error"
	}

	// Additional check: Verify we can query the database
	var result int
	err := h.container.DB.QueryRowContext(ctx, "SELECT 1").Scan(&result)
	if err != nil {
		if err == sql.ErrNoRows {
			return "ok" // No rows is fine for SELECT 1
		}
		return "error"
	}

	return "ok"
}

// formatUptime converts a duration into a human-readable uptime string.
// Examples:
//   - 2h 15m 30s
//   - 1d 5h 23m
//   - 45s
func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return formatDurationString(days, "d", hours, "h", minutes, "m")
	}
	if hours > 0 {
		return formatDurationString(hours, "h", minutes, "m", seconds, "s")
	}
	if minutes > 0 {
		return formatDurationString(minutes, "m", seconds, "s", 0, "")
	}
	return formatDurationString(seconds, "s", 0, "", 0, "")
}

// formatDurationString is a helper to format time units into a string.
func formatDurationString(v1 int, u1 string, v2 int, u2 string, v3 int, u3 string) string {
	result := ""
	if v1 > 0 {
		result += formatUnit(v1, u1)
	}
	if v2 > 0 {
		if result != "" {
			result += " "
		}
		result += formatUnit(v2, u2)
	}
	if v3 > 0 {
		if result != "" {
			result += " "
		}
		result += formatUnit(v3, u3)
	}
	return result
}

// formatUnit formats a single time unit (e.g., "5h", "23m").
func formatUnit(value int, unit string) string {
	if value > 0 {
		return formatInt(value) + unit
	}
	return ""
}

// formatInt converts an integer to a string.
func formatInt(n int) string {
	return string(rune('0' + n/10)) + string(rune('0'+n%10))
}
