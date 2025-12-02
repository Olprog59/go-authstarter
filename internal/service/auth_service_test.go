package service

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/Olprog59/go-authstarter/internal/config"
	"github.com/Olprog59/go-authstarter/internal/domain"
	"github.com/Olprog59/go-authstarter/internal/mocks"
	"github.com/Olprog59/go-authstarter/internal/repository"
	_ "modernc.org/sqlite"

	"golang.org/x/crypto/bcrypt"
)

// authContains checks if a substring is in a string (local to avoid conflicts)
func authContains(s, substr string) bool {
	return strings.Contains(s, substr)
}

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory database: %v", err)
	}

	// Create tables matching the real migrations
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
	`

	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	return db
}

func TestAuthService_ValidateCredentials(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		password      string
		setupMock     func(*mocks.MockUserRepository)
		expectError   bool
		errorContains string
	}{
		{
			name:     "Valid credentials",
			email:    "test@example.com",
			password: "password123",
			setupMock: func(m *mocks.MockUserRepository) {
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
				m.Users[1] = &domain.User{
					ID:            1,
					Email:         "test@example.com",
					Password:      string(hashedPassword),
					EmailVerified: true,
				}
			},
			expectError: false,
		},
		{
			name:     "Invalid password",
			email:    "test@example.com",
			password: "wrongpassword",
			setupMock: func(m *mocks.MockUserRepository) {
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
				m.Users[1] = &domain.User{
					ID:       1,
					Email:    "test@example.com",
					Password: string(hashedPassword),
				}
			},
			expectError:   true,
			errorContains: "invalid credentials",
		},
		{
			name:          "Non-existent user",
			email:         "notfound@example.com",
			password:      "password123",
			setupMock:     func(m *mocks.MockUserRepository) {},
			expectError:   true,
			errorContains: "invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := mocks.NewMockUserRepository()
			mockRefreshStore := mocks.NewMockRefreshTokenStore()
			mockMetrics := mocks.NewMockMetrics()
			tt.setupMock(mockRepo)

			db := setupTestDB(t)
			defer db.Close()

			conf := &config.Config{}
			svc := NewAuthService(mockRepo, mockRefreshStore, conf, db, mockMetrics)

			user, err := svc.ValidateCredentials(context.Background(), tt.email, tt.password)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorContains != "" && !authContains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if user == nil {
					t.Error("Expected user to be returned")
				} else if user.Email != tt.email {
					t.Errorf("Expected email '%s', got '%s'", tt.email, user.Email)
				}
			}
		})
	}
}

func TestAuthService_Login_Success(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := repository.NewSQLiteUser(db)
	refreshStore := repository.NewSQLiteRefreshTokenStore(db)
	mockMetrics := mocks.NewMockMetrics()

	// Create a test user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
	user, err := userRepo.Create(context.Background(), "test@example.com", string(hashedPassword))
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Mark email as verified
	_, err = db.Exec("UPDATE users SET email_verified = 1 WHERE id = ?", user.ID)
	if err != nil {
		t.Fatalf("Failed to verify user: %v", err)
	}

	conf := &config.Config{
		Security: config.SecurityConfig{
			MaxFailedAttempts: 3,
			LockoutDuration:   15 * time.Minute,
		},
		Auth: config.AuthConfig{
			JWTSecret:            "test-secret-key-for-testing-purposes-only",
			AccessTokenDuration:  15 * time.Minute,
			RefreshTokenDuration: 30 * 24 * time.Hour,
		},
	}

	svc := NewAuthService(userRepo, refreshStore, conf, db, mockMetrics)

	returnedUser, tokenPair, err := svc.Login(context.Background(), "test@example.com", "password123", "ip-hash", "ua-hash")

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if returnedUser == nil {
		t.Fatal("Expected user to be returned")
	}

	if tokenPair == nil {
		t.Fatal("Expected token pair to be returned")
	}

	if tokenPair.AccessToken == "" {
		t.Error("Expected access token to be generated")
	}

	if tokenPair.RefreshToken == "" {
		t.Error("Expected refresh token to be generated")
	}
}

func TestAuthService_Login_UnverifiedEmail(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := repository.NewSQLiteUser(db)
	refreshStore := repository.NewSQLiteRefreshTokenStore(db)
	mockMetrics := mocks.NewMockMetrics()

	// Create user without verifying email
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
	_, err := userRepo.Create(context.Background(), "test@example.com", string(hashedPassword))
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	conf := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:           "test-secret-key-for-testing-purposes-only",
			AccessTokenDuration: 15 * time.Minute,
		},
	}

	svc := NewAuthService(userRepo, refreshStore, conf, db, mockMetrics)

	_, _, err = svc.Login(context.Background(), "test@example.com", "password123", "ip-hash", "ua-hash")

	if err == nil {
		t.Fatal("Expected error for unverified email")
	}

	// Just check that we got an error related to verification
	errMsg := err.Error()
	if errMsg != "email not verified" && !strings.Contains(errMsg, "verif") {
		t.Errorf("Expected error about email verification, got: %v", err)
	}
}

func TestAuthService_Login_InvalidCredentials(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := repository.NewSQLiteUser(db)
	refreshStore := repository.NewSQLiteRefreshTokenStore(db)
	mockMetrics := mocks.NewMockMetrics()

	// Create a verified user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
	user, err := userRepo.Create(context.Background(), "test@example.com", string(hashedPassword))
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Mark email as verified
	_, err = db.Exec("UPDATE users SET email_verified = 1 WHERE id = ?", user.ID)
	if err != nil {
		t.Fatalf("Failed to verify user: %v", err)
	}

	conf := &config.Config{
		Security: config.SecurityConfig{
			MaxFailedAttempts: 3,
			LockoutDuration:   15 * time.Minute,
		},
		Auth: config.AuthConfig{
			JWTSecret:            "test-secret-key-for-testing-purposes-only",
			AccessTokenDuration:  15 * time.Minute,
			RefreshTokenDuration: 30 * 24 * time.Hour,
		},
	}

	svc := NewAuthService(userRepo, refreshStore, conf, db, mockMetrics)

	// Test invalid password
	_, _, err = svc.Login(context.Background(), "test@example.com", "wrongpassword", "ip-hash", "ua-hash")

	if err == nil {
		t.Fatal("Expected error for invalid password")
	}

	if !authContains(err.Error(), "invalid credentials") {
		t.Errorf("Expected invalid credentials error, got: %v", err)
	}

	// Verify failed attempt was incremented
	updatedUser, _ := userRepo.GetByEmail(context.Background(), "test@example.com")
	if updatedUser.FailedLoginAttempts != 1 {
		t.Errorf("Expected 1 failed attempt, got %d", updatedUser.FailedLoginAttempts)
	}
}

// TestAuthService_RefreshToken_Success tests successful token refresh with proper IP/UA binding
func TestAuthService_RefreshToken_Success(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := repository.NewSQLiteUser(db)
	refreshStore := repository.NewSQLiteRefreshTokenStore(db)
	mockMetrics := mocks.NewMockMetrics()

	// Create a user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
	user, err := userRepo.Create(context.Background(), "test@example.com", string(hashedPassword))
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Mark email as verified
	_, err = db.Exec("UPDATE users SET email_verified = 1 WHERE id = ?", user.ID)
	if err != nil {
		t.Fatalf("Failed to verify user: %v", err)
	}

	// Create a valid refresh token with IP/UA binding
	validToken := &domain.RefreshToken{
		Token:     "valid-token-12345",
		UserID:    user.ID,
		IssueAt:   time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour), // Valid for 30 days
		IsRevoked: false,
		IPHash:    "test-ip-hash",
		UAHash:    "test-ua-hash",
	}
	if err := refreshStore.Save(context.Background(), validToken); err != nil {
		t.Fatalf("Failed to save valid token: %v", err)
	}

	conf := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:            "test-secret-key-for-testing-purposes-only",
			AccessTokenDuration:  15 * time.Minute,
			RefreshTokenDuration: 30 * 24 * time.Hour,
		},
	}

	svc := NewAuthService(userRepo, refreshStore, conf, db, mockMetrics)

	// Refresh token with matching IP/UA hashes
	tokenPair, err := svc.RefreshToken(context.Background(), "valid-token-12345", "test-ip-hash", "test-ua-hash")

	if err != nil {
		t.Fatalf("Expected successful token refresh, got error: %v", err)
	}

	if tokenPair == nil {
		t.Fatal("Expected token pair, got nil")
	}

	if tokenPair.AccessToken == "" {
		t.Error("Expected access token to be set")
	}

	if tokenPair.RefreshToken == "" {
		t.Error("Expected new refresh token to be set")
	}

	// Verify old token was revoked (should fail to refresh again)
	_, err = svc.RefreshToken(context.Background(), "valid-token-12345", "test-ip-hash", "test-ua-hash")
	if err == nil {
		t.Error("Expected error when reusing old refresh token, but got none")
	}
}

func TestAuthService_RefreshToken_Expired(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := repository.NewSQLiteUser(db)
	refreshStore := repository.NewSQLiteRefreshTokenStore(db)
	mockMetrics := mocks.NewMockMetrics()

	// Create a user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
	user, err := userRepo.Create(context.Background(), "test@example.com", string(hashedPassword))
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create an expired token
	expiredToken := &domain.RefreshToken{
		Token:     "expired-token",
		UserID:    user.ID,
		IssueAt:   time.Now().Add(-31 * 24 * time.Hour),
		ExpiresAt: time.Now().Add(-24 * time.Hour), // Expired yesterday
		IsRevoked: false,
		IPHash:    "ip-hash",
		UAHash:    "ua-hash",
	}
	if err := refreshStore.Save(context.Background(), expiredToken); err != nil {
		t.Fatalf("Failed to save expired token: %v", err)
	}

	conf := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:           "test-secret-key-for-testing-purposes-only",
			AccessTokenDuration: 15 * time.Minute,
		},
	}

	svc := NewAuthService(userRepo, refreshStore, conf, db, mockMetrics)

	_, err = svc.RefreshToken(context.Background(), "expired-token", "ip-hash", "ua-hash")

	if err == nil {
		t.Fatal("Expected error for expired token")
	}

	if !authContains(err.Error(), "invalid") && !authContains(err.Error(), "expired") {
		t.Errorf("Expected error about invalid/expired token, got: %v", err)
	}
}

// TestAuthService_RefreshToken_BindingFailure tests that token refresh fails when IP or UA doesn't match
func TestAuthService_RefreshToken_BindingFailure(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userRepo := repository.NewSQLiteUser(db)
	refreshStore := repository.NewSQLiteRefreshTokenStore(db)
	mockMetrics := mocks.NewMockMetrics()

	// Create a user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
	user, err := userRepo.Create(context.Background(), "test@example.com", string(hashedPassword))
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Mark email as verified
	_, err = db.Exec("UPDATE users SET email_verified = 1 WHERE id = ?", user.ID)
	if err != nil {
		t.Fatalf("Failed to verify user: %v", err)
	}

	// Create a valid refresh token with specific IP/UA binding
	validToken := &domain.RefreshToken{
		Token:     "token-with-binding",
		UserID:    user.ID,
		IssueAt:   time.Now(),
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		IsRevoked: false,
		IPHash:    "original-ip-hash",
		UAHash:    "original-ua-hash",
	}
	if err := refreshStore.Save(context.Background(), validToken); err != nil {
		t.Fatalf("Failed to save token: %v", err)
	}

	conf := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:            "test-secret-key-for-testing-purposes-only",
			AccessTokenDuration:  15 * time.Minute,
			RefreshTokenDuration: 30 * 24 * time.Hour,
		},
	}

	svc := NewAuthService(userRepo, refreshStore, conf, db, mockMetrics)

	// Test with different IP hash (should fail)
	_, err = svc.RefreshToken(context.Background(), "token-with-binding", "different-ip-hash", "original-ua-hash")
	if err == nil {
		t.Error("Expected error when IP hash doesn't match")
	}
	if err != nil && !authContains(err.Error(), "binding") {
		t.Errorf("Expected binding validation error, got: %v", err)
	}

	// Test with different UA hash (should fail)
	_, err = svc.RefreshToken(context.Background(), "token-with-binding", "original-ip-hash", "different-ua-hash")
	if err == nil {
		t.Error("Expected error when UA hash doesn't match")
	}
	if err != nil && !authContains(err.Error(), "binding") {
		t.Errorf("Expected binding validation error, got: %v", err)
	}

	// Test with both different (should fail)
	_, err = svc.RefreshToken(context.Background(), "token-with-binding", "different-ip", "different-ua")
	if err == nil {
		t.Error("Expected error when both IP and UA hashes don't match")
	}
	if err != nil && !authContains(err.Error(), "binding") {
		t.Errorf("Expected binding validation error, got: %v", err)
	}
}

