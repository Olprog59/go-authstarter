package service

import (
	"context"
	"testing"
	"time"

	"github.com/Olprog59/go-authstarter/internal/config"
	"github.com/Olprog59/go-authstarter/internal/domain"
	"github.com/Olprog59/go-authstarter/internal/mocks"
	"golang.org/x/crypto/bcrypt"
)

func TestPasswordService_RequestPasswordReset(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		setupMock   func(*mocks.MockUserRepository)
		expectError bool
	}{
		{
			name:  "Valid email - user exists",
			email: "test@example.com",
			setupMock: func(m *mocks.MockUserRepository) {
				m.Users[1] = &domain.User{
					ID:    1,
					Email: "test@example.com",
				}
			},
			expectError: false,
		},
		{
			name:  "Non-existent email - timing safe",
			email: "notfound@example.com",
			setupMock: func(m *mocks.MockUserRepository) {
				// No user
			},
			expectError: false, // Should not error to prevent enumeration
		},
		{
			name:        "Invalid email format",
			email:       "invalid-email",
			setupMock:   func(m *mocks.MockUserRepository) {},
			expectError: false, // Should not error to prevent enumeration
		},
		{
			name:        "Empty email",
			email:       "",
			setupMock:   func(m *mocks.MockUserRepository) {},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := mocks.NewMockUserRepository()
			mockRefreshStore := mocks.NewMockRefreshTokenStore()
			mockEmailSender := mocks.NewMockEmailSender()
			tt.setupMock(mockRepo)

			conf := &config.Config{
				Server: config.ServerConfig{
					BaseURL: "http://localhost:8080",
				},
			}

			svc, svcErr := NewPasswordService(mockRepo, mockRefreshStore, mockEmailSender, conf)
			if svcErr != nil {
				t.Fatalf("Failed to create password service: %v", svcErr)
			}

			err := svc.RequestPasswordReset(context.Background(), tt.email)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestPasswordService_ResetPassword(t *testing.T) {
	tests := []struct {
		name          string
		token         string
		newPassword   string
		setupMock     func(*mocks.MockUserRepository)
		expectError   bool
		errorContains string
	}{
		{
			name:        "Valid token and password",
			token:       "valid-token",
			newPassword: "NewP@ssw0rd",
			setupMock: func(m *mocks.MockUserRepository) {
				m.Users[1] = &domain.User{
					ID:    1,
					Email: "test@example.com",
				}
				// Use the repository method to set the token
				future := time.Now().Add(1 * time.Hour)
				m.SetPasswordResetToken(context.Background(), "test@example.com", "valid-token", future)
			},
			expectError: false,
		},
		{
			name:        "Expired token",
			token:       "expired-token",
			newPassword: "NewP@ssw0rd",
			setupMock: func(m *mocks.MockUserRepository) {
				m.Users[1] = &domain.User{
					ID:    1,
					Email: "test@example.com",
				}
				past := time.Now().Add(-1 * time.Hour)
				m.SetPasswordResetToken(context.Background(), "test@example.com", "expired-token", past)
			},
			expectError:   true,
			errorContains: "invalid",
		},
		{
			name:          "Invalid token",
			token:         "invalid-token",
			newPassword:   "NewP@ssw0rd",
			setupMock:     func(m *mocks.MockUserRepository) {},
			expectError:   true,
			errorContains: "invalid",
		},
		{
			name:  "Weak password",
			token: "valid-token",
			newPassword: "weak",
			setupMock: func(m *mocks.MockUserRepository) {
				m.Users[1] = &domain.User{
					ID:    1,
					Email: "test@example.com",
				}
				future := time.Now().Add(1 * time.Hour)
				m.SetPasswordResetToken(context.Background(), "test@example.com", "valid-token", future)
			},
			expectError:   true,
			errorContains: "strength",
		},
		{
			name:  "Empty password",
			token: "valid-token",
			newPassword: "",
			setupMock: func(m *mocks.MockUserRepository) {
				m.Users[1] = &domain.User{
					ID:    1,
					Email: "test@example.com",
				}
				future := time.Now().Add(1 * time.Hour)
				m.SetPasswordResetToken(context.Background(), "test@example.com", "valid-token", future)
			},
			expectError:   true,
			errorContains: "password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := mocks.NewMockUserRepository()
			mockRefreshStore := mocks.NewMockRefreshTokenStore()
			mockEmailSender := mocks.NewMockEmailSender()
			tt.setupMock(mockRepo)

			conf := &config.Config{
				Security: config.SecurityConfig{
					BcryptCost: bcrypt.MinCost,
				},
			}

			svc, svcErr := NewPasswordService(mockRepo, mockRefreshStore, mockEmailSender, conf)
			if svcErr != nil {
				t.Fatalf("Failed to create password service: %v", svcErr)
			}

			err := svc.ResetPassword(context.Background(), tt.token, tt.newPassword)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				// Verify password was updated
				user := mockRepo.Users[1]
				if user != nil {
					// Verify new password works
					err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(tt.newPassword))
					if err != nil {
						t.Error("Password was not properly updated")
					}
				}

				// Verify tokens were revoked
				if mockRefreshStore.RevokeAllCalls == 0 {
					t.Error("Expected refresh tokens to be revoked")
				}
			}
		})
	}
}

func TestPasswordService_ChangePassword(t *testing.T) {
	tests := []struct {
		name            string
		userID          int64
		currentPassword string
		newPassword     string
		setupMock       func(*mocks.MockUserRepository)
		expectError     bool
		errorContains   string
	}{
		{
			name:            "Valid password change",
			userID:          1,
			currentPassword: "OldP@ssw0rd",
			newPassword:     "NewP@ssw0rd",
			setupMock: func(m *mocks.MockUserRepository) {
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("OldP@ssw0rd"), bcrypt.MinCost)
				m.Users[1] = &domain.User{
					ID:       1,
					Email:    "test@example.com",
					Password: string(hashedPassword),
				}
			},
			expectError: false,
		},
		{
			name:            "Wrong current password",
			userID:          1,
			currentPassword: "WrongPassword",
			newPassword:     "NewP@ssw0rd",
			setupMock: func(m *mocks.MockUserRepository) {
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("OldP@ssw0rd"), bcrypt.MinCost)
				m.Users[1] = &domain.User{
					ID:       1,
					Email:    "test@example.com",
					Password: string(hashedPassword),
				}
			},
			expectError:   true,
			errorContains: "current password",
		},
		{
			name:            "Weak new password",
			userID:          1,
			currentPassword: "OldP@ssw0rd",
			newPassword:     "weak",
			setupMock: func(m *mocks.MockUserRepository) {
				hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("OldP@ssw0rd"), bcrypt.MinCost)
				m.Users[1] = &domain.User{
					ID:       1,
					Email:    "test@example.com",
					Password: string(hashedPassword),
				}
			},
			expectError:   true,
			errorContains: "strength",
		},
		{
			name:            "Non-existent user",
			userID:          999,
			currentPassword: "OldP@ssw0rd",
			newPassword:     "NewP@ssw0rd",
			setupMock:       func(m *mocks.MockUserRepository) {},
			expectError:     true,
			errorContains:   "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := mocks.NewMockUserRepository()
			mockRefreshStore := mocks.NewMockRefreshTokenStore()
			mockEmailSender := mocks.NewMockEmailSender()
			tt.setupMock(mockRepo)

			conf := &config.Config{
				Security: config.SecurityConfig{
					BcryptCost: bcrypt.MinCost,
				},
			}

			svc, svcErr := NewPasswordService(mockRepo, mockRefreshStore, mockEmailSender, conf)
			if svcErr != nil {
				t.Fatalf("Failed to create password service: %v", svcErr)
			}

			err := svc.ChangePassword(context.Background(), tt.userID, tt.currentPassword, tt.newPassword)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				// Verify password was updated
				user := mockRepo.Users[tt.userID]
				if user != nil {
					err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(tt.newPassword))
					if err != nil {
						t.Error("Password was not properly updated")
					}
				}

				// Verify tokens were revoked
				if mockRefreshStore.RevokeAllCalls == 0 {
					t.Error("Expected refresh tokens to be revoked")
				}
			}
		})
	}
}
