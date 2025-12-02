package web

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Olprog59/go-authstarter/internal/app"
	"github.com/Olprog59/go-authstarter/internal/config"
	"github.com/Olprog59/go-authstarter/internal/metrics"
	"github.com/Olprog59/go-authstarter/internal/repository"
	"github.com/Olprog59/go-authstarter/internal/service"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// TestAdmin_ListUsers tests the ListUsers handler with pagination
func TestAdmin_ListUsers(t *testing.T) {
	handler, db := setupAdminTestHandler(t)
	defer db.Close()

	// Create 25 test users for pagination testing
	for i := 1; i <= 25; i++ {
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), 10)
		_, err := db.Exec(`
			INSERT INTO users (email, password, role, email_verified)
			VALUES (?, ?, 'user', 1)
		`, fmt.Sprintf("user%d@example.com", i), string(hashedPassword))
		if err != nil {
			t.Fatalf("Failed to create test user %d: %v", i, err)
		}
	}

	tests := []struct {
		name             string
		queryParams      string
		expectedStatus   int
		expectedMinUsers int
		expectedMaxUsers int
		checkPagination  func(*testing.T, map[string]interface{})
	}{
		{
			name:             "default pagination (page 1, limit 20)",
			queryParams:      "",
			expectedStatus:   http.StatusOK,
			expectedMinUsers: 20,
			expectedMaxUsers: 20,
			checkPagination: func(t *testing.T, resp map[string]interface{}) {
				pagination := resp["pagination"].(map[string]interface{})
				if pagination["page"].(float64) != 1 {
					t.Errorf("Expected page 1, got %v", pagination["page"])
				}
				if pagination["limit"].(float64) != 20 {
					t.Errorf("Expected limit 20, got %v", pagination["limit"])
				}
				if pagination["total"].(float64) != 25 {
					t.Errorf("Expected total 25, got %v", pagination["total"])
				}
			},
		},
		{
			name:             "page 2 with limit 10",
			queryParams:      "?page=2&limit=10",
			expectedStatus:   http.StatusOK,
			expectedMinUsers: 10,
			expectedMaxUsers: 10,
			checkPagination: func(t *testing.T, resp map[string]interface{}) {
				pagination := resp["pagination"].(map[string]interface{})
				if pagination["page"].(float64) != 2 {
					t.Errorf("Expected page 2, got %v", pagination["page"])
				}
				if pagination["limit"].(float64) != 10 {
					t.Errorf("Expected limit 10, got %v", pagination["limit"])
				}
			},
		},
		{
			name:             "page 3 with limit 10 (only 5 users left)",
			queryParams:      "?page=3&limit=10",
			expectedStatus:   http.StatusOK,
			expectedMinUsers: 5,
			expectedMaxUsers: 5,
		},
		{
			name:             "limit exceeds max (should cap at 100)",
			queryParams:      "?limit=200",
			expectedStatus:   http.StatusOK,
			expectedMinUsers: 25,
			expectedMaxUsers: 25,
			checkPagination: func(t *testing.T, resp map[string]interface{}) {
				pagination := resp["pagination"].(map[string]interface{})
				if pagination["limit"].(float64) != 100 {
					t.Errorf("Expected limit capped at 100, got %v", pagination["limit"])
				}
			},
		},
		{
			name:             "invalid page (negative)",
			queryParams:      "?page=-1",
			expectedStatus:   http.StatusOK, // Should default to page 1
			expectedMinUsers: 20,
			expectedMaxUsers: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/admin/users"+tt.queryParams, nil)
			rec := httptest.NewRecorder()

			handler.ListUsers(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, rec.Code, rec.Body.String())
			}

			if tt.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}

				users := response["users"].([]interface{})
				if len(users) < tt.expectedMinUsers || len(users) > tt.expectedMaxUsers {
					t.Errorf("Expected %d-%d users, got %d", tt.expectedMinUsers, tt.expectedMaxUsers, len(users))
				}

				// Check pagination metadata exists
				if _, ok := response["pagination"]; !ok {
					t.Error("Expected pagination metadata in response")
				}

				if tt.checkPagination != nil {
					tt.checkPagination(t, response)
				}
			}
		})
	}
}

// TestAdmin_DeleteUser tests the DeleteUser handler
func TestAdmin_DeleteUser(t *testing.T) {
	handler, db := setupAdminTestHandler(t)
	defer db.Close()

	// Create a test user to delete
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), 10)
	result, err := db.Exec(`
		INSERT INTO users (email, password, role, email_verified)
		VALUES (?, ?, 'user', 1)
	`, "delete@example.com", string(hashedPassword))
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	userID, _ := result.LastInsertId()

	tests := []struct {
		name           string
		userID         string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "successful deletion",
			userID:         fmt.Sprintf("%d", userID),
			expectedStatus: http.StatusOK,
		},
		{
			name:           "delete non-existent user",
			userID:         "99999",
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Failed to delete user",
		},
		{
			name:           "invalid user ID",
			userID:         "invalid",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid user ID",
		},
		{
			name:           "missing user ID",
			userID:         "",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "User ID is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+tt.userID, nil)
			req.SetPathValue("id", tt.userID)
			rec := httptest.NewRecorder()

			handler.DeleteUser(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, rec.Code, rec.Body.String())
			}

			if tt.expectedError != "" {
				body := rec.Body.String()
				if body == "" || !contains(body, tt.expectedError) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.expectedError, body)
				}
			}

			// If deletion was successful, verify user is actually deleted
			if tt.name == "successful deletion" && rec.Code == http.StatusOK {
				var count int
				err := db.QueryRow("SELECT COUNT(*) FROM users WHERE id = ?", userID).Scan(&count)
				if err != nil {
					t.Fatalf("Failed to check if user was deleted: %v", err)
				}
				if count != 0 {
					t.Error("User was not deleted from database")
				}
			}
		})
	}
}

// TestAdmin_UpdateUserRole tests the UpdateUserRole handler
func TestAdmin_UpdateUserRole(t *testing.T) {
	handler, db := setupAdminTestHandler(t)
	defer db.Close()

	// Create a test user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), 10)
	result, err := db.Exec(`
		INSERT INTO users (email, password, role, email_verified)
		VALUES (?, ?, 'user', 1)
	`, "roletest@example.com", string(hashedPassword))
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	userID, _ := result.LastInsertId()

	tests := []struct {
		name           string
		userID         string
		requestBody    interface{}
		expectedStatus int
		expectedError  string
		verifyRole     string
	}{
		{
			name:   "successful role update to moderator",
			userID: fmt.Sprintf("%d", userID),
			requestBody: map[string]string{
				"role": "moderator",
			},
			expectedStatus: http.StatusOK,
			verifyRole:     "moderator",
		},
		{
			name:   "successful role update to admin",
			userID: fmt.Sprintf("%d", userID),
			requestBody: map[string]string{
				"role": "admin",
			},
			expectedStatus: http.StatusOK,
			verifyRole:     "admin",
		},
		{
			name:   "invalid role",
			userID: fmt.Sprintf("%d", userID),
			requestBody: map[string]string{
				"role": "superuser",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid role",
		},
		{
			name:   "empty role",
			userID: fmt.Sprintf("%d", userID),
			requestBody: map[string]string{
				"role": "",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid role",
		},
		{
			name:           "invalid JSON",
			userID:         fmt.Sprintf("%d", userID),
			requestBody:    "not json",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "invalid user ID",
			userID: "invalid",
			requestBody: map[string]string{
				"role": "moderator",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid user ID",
		},
		{
			name:   "request body too large",
			userID: fmt.Sprintf("%d", userID),
			requestBody: map[string]string{
				"role": string(make([]byte, 2*1024*1024)), // 2MB
			},
			expectedStatus: http.StatusRequestEntityTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var reqBody *bytes.Buffer
			if str, ok := tt.requestBody.(string); ok {
				reqBody = bytes.NewBufferString(str)
			} else {
				jsonBody, _ := json.Marshal(tt.requestBody)
				reqBody = bytes.NewBuffer(jsonBody)
			}

			req := httptest.NewRequest(http.MethodPatch, "/api/admin/users/"+tt.userID+"/role", reqBody)
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("id", tt.userID)
			rec := httptest.NewRecorder()

			handler.UpdateUserRole(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, rec.Code, rec.Body.String())
			}

			if tt.expectedError != "" {
				body := rec.Body.String()
				if !contains(body, tt.expectedError) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.expectedError, body)
				}
			}

			// Verify role was actually updated in database
			if tt.verifyRole != "" && rec.Code == http.StatusOK {
				var role string
				err := db.QueryRow("SELECT role FROM users WHERE id = ?", userID).Scan(&role)
				if err != nil {
					t.Fatalf("Failed to check user role: %v", err)
				}
				if role != tt.verifyRole {
					t.Errorf("Expected role '%s', got '%s'", tt.verifyRole, role)
				}
			}
		})
	}
}

// TestAdmin_GetUserStats tests the GetUserStats handler
func TestAdmin_GetUserStats(t *testing.T) {
	handler, db := setupAdminTestHandler(t)
	defer db.Close()

	// Create test users with different roles and verification states
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), 10)

	// 10 verified users
	for i := 1; i <= 10; i++ {
		db.Exec(`
			INSERT INTO users (email, password, role, email_verified)
			VALUES (?, ?, 'user', 1)
		`, fmt.Sprintf("verified%d@example.com", i), string(hashedPassword))
	}

	// 5 unverified users
	for i := 1; i <= 5; i++ {
		db.Exec(`
			INSERT INTO users (email, password, role, email_verified)
			VALUES (?, ?, 'user', 0)
		`, fmt.Sprintf("unverified%d@example.com", i), string(hashedPassword))
	}

	// 2 moderators
	for i := 1; i <= 2; i++ {
		db.Exec(`
			INSERT INTO users (email, password, role, email_verified)
			VALUES (?, ?, 'moderator', 1)
		`, fmt.Sprintf("moderator%d@example.com", i), string(hashedPassword))
	}

	// 1 admin
	db.Exec(`
		INSERT INTO users (email, password, role, email_verified)
		VALUES (?, ?, 'admin', 1)
	`, "admin@example.com", string(hashedPassword))

	req := httptest.NewRequest(http.MethodGet, "/api/moderator/stats", nil)
	rec := httptest.NewRecorder()

	handler.GetUserStats(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	var stats map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Verify stats
	if stats["total_users"].(float64) != 18 {
		t.Errorf("Expected total_users 18, got %v", stats["total_users"])
	}

	if stats["verified_users"].(float64) != 13 {
		t.Errorf("Expected verified_users 13, got %v", stats["verified_users"])
	}

	roles := stats["roles"].(map[string]interface{})
	if roles["user"].(float64) != 15 {
		t.Errorf("Expected 15 users with 'user' role, got %v", roles["user"])
	}
	if roles["moderator"].(float64) != 2 {
		t.Errorf("Expected 2 moderators, got %v", roles["moderator"])
	}
	if roles["admin"].(float64) != 1 {
		t.Errorf("Expected 1 admin, got %v", roles["admin"])
	}
}

// setupAdminTestHandler creates a test handler with real services and in-memory DB
func setupAdminTestHandler(t *testing.T) (*Handler, *sql.DB) {
	t.Helper()

	db := setupTestDB(t)

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
			BcryptCost:      10,
			LockoutDuration: 15 * time.Minute,
			TrustedProxies:  []string{},
		},
		SMTP: config.SMTPConfig{
			Host:     "localhost",
			Port:     1025,
			From:     "test@example.com",
			Username: "",
			Password: "",
		},
	}

	// Use a new registry for each test to avoid conflicts
	localRegistry := prometheus.NewRegistry()
	metricsCollector := metrics.NewMetrics(localRegistry)

	userRepo := repository.NewSQLiteUser(db)
	refreshTokenStore := repository.NewSQLiteRefreshTokenStore(db)

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

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) >= len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
