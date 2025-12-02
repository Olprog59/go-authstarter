package web

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Olprog59/go-authstarter/internal/app"
	"github.com/Olprog59/go-authstarter/internal/config"
	"github.com/Olprog59/go-authstarter/internal/dto"
	"github.com/Olprog59/go-authstarter/internal/metrics"
	"github.com/Olprog59/go-authstarter/internal/repository"
	"github.com/Olprog59/go-authstarter/internal/service"
	"github.com/Olprog59/go-authstarter/internal/service/auth"
	"github.com/prometheus/client_golang/prometheus"
	_ "modernc.org/sqlite"
)

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory database: %v", err)
	}

	// Create schema
	schema := `
	CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'user',
		email_verified BOOLEAN NOT NULL DEFAULT 0,
		verification_token TEXT,
		verification_expires_at TIMESTAMP,
		failed_login_attempts INTEGER NOT NULL DEFAULT 0,
		locked_until TIMESTAMP,
		password_reset_token TEXT,
		password_reset_expires_at TIMESTAMP,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		deleted_at TIMESTAMP
	);

	CREATE TABLE refresh_tokens (
		token TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		issue_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		expires_at TIMESTAMP NOT NULL,
		is_revoked BOOLEAN NOT NULL DEFAULT 0,
		ip_hash TEXT NOT NULL DEFAULT '',
		ua_hash TEXT NOT NULL DEFAULT '',
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE roles (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL
	);

	CREATE TABLE permissions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		description TEXT
	);

	CREATE TABLE role_permissions (
		role_name TEXT NOT NULL,
		permission_name TEXT NOT NULL,
		PRIMARY KEY (role_name, permission_name),
		FOREIGN KEY (role_name) REFERENCES roles(name) ON DELETE CASCADE,
		FOREIGN KEY (permission_name) REFERENCES permissions(name) ON DELETE CASCADE
	);
	`

	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	return db
}

// setupIntegrationTestHandler creates a real handler with real services and in-memory DB
func setupIntegrationTestHandler(t *testing.T) (*Handler, *sql.DB) {
	t.Helper()

	db := setupTestDB(t)

	// Create real config
	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:            "test-secret-must-be-at-least-32-characters-long-for-security",
			AccessTokenDuration:  15 * time.Minute,
			RefreshTokenDuration: 30 * 24 * time.Hour,
			CookiePath:           "/",
			CookieSecure:         false,
			CookieDomain:         "",
		},
		Security: config.SecurityConfig{
			BcryptCost:       10,
			LockoutDuration:  15 * time.Minute,
			TrustedProxies:   []string{},
		},
		SMTP: config.SMTPConfig{
			Host:     "localhost",
			Port:     1025,
			From:     "test@example.com",
			Username: "",
			Password: "",
		},
	}

	// Create metrics with a local registry to avoid conflicts between tests
	// Pass a new prometheus registry to avoid "duplicate metrics collector registration"
	localRegistry := prometheus.NewRegistry()
	metricsCollector := metrics.NewMetrics(localRegistry)

	// Create real repositories
	userRepo := repository.NewSQLiteUser(db)
	refreshTokenStore := repository.NewSQLiteRefreshTokenStore(db)

	// Create real services
	emailSvc, err := service.NewEmailService(cfg)
	if err != nil {
		t.Fatalf("Failed to create email service: %v", err)
	}
	userSvc := service.NewUserService(userRepo, refreshTokenStore, cfg)
	authSvc := service.NewAuthService(userRepo, refreshTokenStore, cfg, db, metricsCollector)
	verificationSvc, err := service.NewVerificationService(userRepo, emailSvc, cfg)
	if err != nil {
		t.Fatalf("Failed to create verification service: %v", err)
	}
	passwordSvc, err := service.NewPasswordService(userRepo, refreshTokenStore, emailSvc, cfg)
	if err != nil {
		t.Fatalf("Failed to create password service: %v", err)
	}

	// Create container
	container := &app.Container{
		DB:                db,
		Config:            cfg,
		UserRepo:          userRepo,
		RefreshTokenStore: refreshTokenStore,
		UserSvc:           userSvc,
		AuthSvc:           authSvc,
		VerificationSvc:   verificationSvc,
		PasswordSvc:       passwordSvc,
		Metrics:           metricsCollector,
	}

	handler := NewHandler(container)

	return handler, db
}

// TestIntegration_RegisterAndLogin tests the complete registration and login flow
func TestIntegration_RegisterAndLogin(t *testing.T) {
	handler, db := setupIntegrationTestHandler(t)
	defer db.Close()

	// Test 1: Register a new user
	t.Run("Register", func(t *testing.T) {
		reqBody := dto.UserDTOReq{
			Username: "test@example.com",
			Password: "ValidPass123!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.Register(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
		}

		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if msg, ok := response["message"].(string); !ok || msg == "" {
			t.Errorf("Expected message in response, got: %v", response)
		}
	})

	// Test 2: Try to register with same email (should return success for security)
	t.Run("Register duplicate email", func(t *testing.T) {
		reqBody := dto.UserDTOReq{
			Username: "test@example.com",
			Password: "ValidPass123!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.Register(rec, req)

		// Should still return 200 to prevent email enumeration
		if rec.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rec.Code)
		}
	})

	// Test 3: Try to login before email verification (should fail)
	t.Run("Login before verification", func(t *testing.T) {
		reqBody := dto.UserDTOReq{
			Username: "test@example.com",
			Password: "ValidPass123!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.Login(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rec.Code)
		}
	})

	// Test 4: Manually verify email in database
	_, err := db.Exec("UPDATE users SET email_verified = 1 WHERE email = ?", "test@example.com")
	if err != nil {
		t.Fatalf("Failed to verify email: %v", err)
	}

	// Test 5: Login after verification (should succeed)
	t.Run("Login after verification", func(t *testing.T) {
		reqBody := dto.UserDTOReq{
			Username: "test@example.com",
			Password: "ValidPass123!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.Login(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
		}

		// Check cookies are set
		cookies := rec.Result().Cookies()
		if len(cookies) < 2 {
			t.Errorf("Expected at least 2 cookies, got %d", len(cookies))
		}

		// Verify response contains user data
		var response dto.UserLoginDTOResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response.Email != "test@example.com" {
			t.Errorf("Expected email 'test@example.com', got '%s'", response.Email)
		}
	})

	// Test 6: Login with wrong password
	t.Run("Login with wrong password", func(t *testing.T) {
		reqBody := dto.UserDTOReq{
			Username: "test@example.com",
			Password: "WrongPassword123!",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.Login(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rec.Code)
		}
	})
}

// TestIntegration_Me tests the /me endpoint
func TestIntegration_Me(t *testing.T) {
	handler, db := setupIntegrationTestHandler(t)
	defer db.Close()

	// Create and verify a user
	_, err := db.Exec(`
		INSERT INTO users (email, password, role, email_verified)
		VALUES (?, ?, 'user', 1)
	`, "test@example.com", "$2a$10$fakehash")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Get user ID
	var userID int64
	err = db.QueryRow("SELECT id FROM users WHERE email = ?", "test@example.com").Scan(&userID)
	if err != nil {
		t.Fatalf("Failed to get user ID: %v", err)
	}

	t.Run("Valid user in context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/me", nil)

		// Add claims to context (simulating Auth middleware)
		claims := &auth.CustomClaims{
			Role: "user",
		}
		claims.Subject = strconv.FormatInt(userID, 10)
		ctx := context.WithValue(req.Context(), ClaimsContextKey, claims)
		req = req.WithContext(ctx)

		rec := httptest.NewRecorder()
		handler.Me(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
		}

		var response dto.UserLoginDTOResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse response: %v", err)
		}

		if response.Email != "test@example.com" {
			t.Errorf("Expected email 'test@example.com', got '%s'", response.Email)
		}
	})

	t.Run("Missing claims in context", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		rec := httptest.NewRecorder()

		handler.Me(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rec.Code)
		}
	})
}

// TestIntegration_VerifyEmail tests email verification
func TestIntegration_VerifyEmail(t *testing.T) {
	handler, db := setupIntegrationTestHandler(t)
	defer db.Close()

	// Create a user with verification token
	verificationToken := "test-token-123"
	expiresAt := time.Now().Add(24 * time.Hour)

	_, err := db.Exec(`
		INSERT INTO users (email, password, role, email_verified, verification_token, verification_expires_at)
		VALUES (?, ?, 'user', 0, ?, ?)
	`, "test@example.com", "$2a$10$fakehash", verificationToken, expiresAt)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	t.Run("Valid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/verify-email?token="+verificationToken, nil)
		rec := httptest.NewRecorder()

		handler.VerifyEmail(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
		}

		// Verify user is marked as verified in DB
		var verified bool
		err := db.QueryRow("SELECT email_verified FROM users WHERE email = ?", "test@example.com").Scan(&verified)
		if err != nil {
			t.Fatalf("Failed to check verification status: %v", err)
		}

		if !verified {
			t.Error("User should be marked as verified")
		}
	})

	t.Run("Missing token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/verify-email", nil)
		rec := httptest.NewRecorder()

		handler.VerifyEmail(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("Expected status 400, got %d", rec.Code)
		}
	})
}

// TestIntegration_InvalidJSON tests handling of malformed JSON
func TestIntegration_InvalidJSON(t *testing.T) {
	handler, db := setupIntegrationTestHandler(t)
	defer db.Close()

	tests := []struct {
		name    string
		handler http.HandlerFunc
		url     string
	}{
		{"Login", handler.Login, "/api/login"},
		{"Register", handler.Register, "/api/register"},
		{"RequestPasswordReset", handler.RequestPasswordReset, "/api/request-password-reset"},
		{"ResetPassword", handler.ResetPassword, "/api/reset-password"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tt.url, bytes.NewBufferString("invalid json {"))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			tt.handler(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("Expected status 400, got %d for %s", rec.Code, tt.name)
			}
		})
	}
}

// TestIntegration_WeakPassword tests password strength validation
func TestIntegration_WeakPassword(t *testing.T) {
	handler, db := setupIntegrationTestHandler(t)
	defer db.Close()

	weakPasswords := []string{
		"short",       // Too short
		"nouppercase1!", // No uppercase
		"NOLOWERCASE1!", // No lowercase
		"NoDigits!",   // No digits
		"NoSpecial123", // No special char
	}

	for _, weakPass := range weakPasswords {
		t.Run("Weak password: "+weakPass, func(t *testing.T) {
			reqBody := dto.UserDTOReq{
				Username: "test@example.com",
				Password: weakPass,
			}
			body, _ := json.Marshal(reqBody)

			req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			handler.Register(rec, req)

			if rec.Code != http.StatusInternalServerError && rec.Code != http.StatusBadRequest {
				t.Errorf("Expected status 400 or 500 for weak password, got %d", rec.Code)
			}
		})
	}
}
