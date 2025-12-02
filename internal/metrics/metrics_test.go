package metrics_test

import (
	"strings"
	"testing"
	"time"

	"github.com/Olprog59/go-authstarter/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestNewMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetrics(reg)
	assert.NotNil(t, m)
	// Check a few metrics to make sure they are initialized
	assert.NotNil(t, m.LoginAttempts)
	assert.NotNil(t, m.HTTPRequestsTotal)
	assert.NotNil(t, m.DatabaseConnections)
}

func TestRecordLoginAttempt(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetrics(reg)
	m.RecordLoginAttempt("success")
	assert.Equal(t, 1.0, testutil.ToFloat64(m.LoginAttempts.WithLabelValues("success")))
	m.RecordLoginAttempt("failure")
	m.RecordLoginAttempt("failure")
	assert.Equal(t, 2.0, testutil.ToFloat64(m.LoginAttempts.WithLabelValues("failure")))
}

func TestRecordRegistration(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetrics(reg)
	m.RecordRegistration()
	assert.Equal(t, 1.0, testutil.ToFloat64(m.RegistrationTotal))
}

func TestRecordEmailVerification(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetrics(reg)
	m.RecordEmailVerification("success")
	assert.Equal(t, 1.0, testutil.ToFloat64(m.EmailVerifications.WithLabelValues("success")))
}

func TestRecordTokenRefresh(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetrics(reg)
	m.RecordTokenRefresh("success")
	assert.Equal(t, 1.0, testutil.ToFloat64(m.TokenRefreshes.WithLabelValues("success")))
}

func TestRecordAccountLockout(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetrics(reg)
	m.RecordAccountLockout()
	assert.Equal(t, 1.0, testutil.ToFloat64(m.AccountLockouts))
}

func TestRecordHTTPRequest(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetrics(reg)
	m.RecordHTTPRequest("GET", "/test", 200)
	assert.Equal(t, 1.0, testutil.ToFloat64(m.HTTPRequestsTotal.WithLabelValues("GET", "/test", "200")))
}

func TestRecordHTTPDuration(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetrics(reg)
	m.RecordHTTPDuration("GET", "/test", 1*time.Second)

	expected := `
# HELP http_request_duration_seconds HTTP request latency in seconds
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{method="GET",path="/test",le="0.01"} 0
http_request_duration_seconds_bucket{method="GET",path="/test",le="0.05"} 0
http_request_duration_seconds_bucket{method="GET",path="/test",le="0.1"} 0
http_request_duration_seconds_bucket{method="GET",path="/test",le="0.25"} 0
http_request_duration_seconds_bucket{method="GET",path="/test",le="0.5"} 0
http_request_duration_seconds_bucket{method="GET",path="/test",le="1"} 1
http_request_duration_seconds_bucket{method="GET",path="/test",le="2.5"} 1
http_request_duration_seconds_bucket{method="GET",path="/test",le="5"} 1
http_request_duration_seconds_bucket{method="GET",path="/test",le="10"} 1
http_request_duration_seconds_bucket{method="GET",path="/test",le="+Inf"} 1
http_request_duration_seconds_sum{method="GET",path="/test"} 1
http_request_duration_seconds_count{method="GET",path="/test"} 1
`
	err := testutil.CollectAndCompare(m.HTTPRequestDuration, strings.NewReader(expected), "http_request_duration_seconds")
	assert.NoError(t, err)
}

func TestIncrementDecrementActiveConnections(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetrics(reg)
	m.IncrementActiveConnections()
	assert.Equal(t, 1.0, testutil.ToFloat64(m.ActiveConnections))
	m.DecrementActiveConnections()
	assert.Equal(t, 0.0, testutil.ToFloat64(m.ActiveConnections))
}

func TestRecordRateLimitHit(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetrics(reg)
	m.RecordRateLimitHit("/login")
	assert.Equal(t, 1.0, testutil.ToFloat64(m.RateLimitHits.WithLabelValues("/login")))
}

func TestRecordCSRFFailure(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetrics(reg)
	m.RecordCSRFFailure()
	assert.Equal(t, 1.0, testutil.ToFloat64(m.CSRFFailures))
}

func TestRecordInvalidToken(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetrics(reg)
	m.RecordInvalidToken()
	assert.Equal(t, 1.0, testutil.ToFloat64(m.InvalidTokens))
}

func TestRecordTokenBindingFailure(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetrics(reg)
	m.RecordTokenBindingFailure()
	assert.Equal(t, 1.0, testutil.ToFloat64(m.TokenBindingFails))
}

func TestUpdateDatabaseConnections(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetrics(reg)
	m.UpdateDatabaseConnections(10)
	assert.Equal(t, 10.0, testutil.ToFloat64(m.DatabaseConnections))
}

func TestSetBackgroundTaskStatus(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetrics(reg)
	m.SetBackgroundTaskStatus("test_task", true)
	assert.Equal(t, 1.0, testutil.ToFloat64(m.BackgroundTasks.WithLabelValues("test_task")))
	m.SetBackgroundTaskStatus("test_task", false)
	assert.Equal(t, 0.0, testutil.ToFloat64(m.BackgroundTasks.WithLabelValues("test_task")))
}

func TestRecordPermissionDenial(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetrics(reg)
	m.RecordPermissionDenial("users:read")
	assert.Equal(t, 1.0, testutil.ToFloat64(m.PermissionDenials.WithLabelValues("users:read")))
}
