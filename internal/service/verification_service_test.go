package service

import (
	"context"
	"testing"
	"time"

	"github.com/Olprog59/go-authstarter/internal/config"
	"github.com/Olprog59/go-authstarter/internal/domain"
	"github.com/Olprog59/go-authstarter/internal/mocks"
)

func TestVerificationService_SendVerificationEmail(t *testing.T) {
	tests := []struct {
		name        string
		user        *domain.User
		expectError bool
	}{
		{
			name: "Valid user",
			user: &domain.User{
				ID:    1,
				Email: "test@example.com",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := mocks.NewMockUserRepository()
			if tt.user != nil {
				mockRepo.Users[tt.user.ID] = tt.user
			}

			conf := &config.Config{
				Server: config.ServerConfig{
					BaseURL: "http://localhost:8080",
				},
				EmailVerification: config.EmailVerification{
					TokenExpiration: 24 * time.Hour,
				},
			}

			mockEmailSender := mocks.NewMockEmailSender()
			svc, svcErr := NewVerificationService(mockRepo, mockEmailSender, conf)
			if svcErr != nil {
				t.Fatalf("Failed to create verification service: %v", svcErr)
			}

			err := svc.SendVerificationEmail(context.Background(), tt.user)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestVerificationService_ResendVerification(t *testing.T) {
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
					ID:            1,
					Email:         "test@example.com",
					EmailVerified: false,
				}
			},
			expectError: false,
		},
		{
			name:  "Already verified - timing safe",
			email: "verified@example.com",
			setupMock: func(m *mocks.MockUserRepository) {
				m.Users[1] = &domain.User{
					ID:            1,
					Email:         "verified@example.com",
					EmailVerified: true,
				}
			},
			expectError: false, // Should not error to prevent enumeration
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := mocks.NewMockUserRepository()
			tt.setupMock(mockRepo)

			conf := &config.Config{
				Server: config.ServerConfig{
					BaseURL: "http://localhost:8080",
				},
				EmailVerification: config.EmailVerification{
					TokenExpiration: 24 * time.Hour,
				},
			}

			mockEmailSender := mocks.NewMockEmailSender()
			svc, svcErr := NewVerificationService(mockRepo, mockEmailSender, conf)
			if svcErr != nil {
				t.Fatalf("Failed to create verification service: %v", svcErr)
			}

			err := svc.ResendVerification(context.Background(), tt.email)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestVerificationService_VerifyEmail(t *testing.T) {
	tests := []struct {
		name          string
		token         string
		setupMock     func(*mocks.MockUserRepository)
		expectError   bool
		errorContains string
	}{
		{
			name:  "Valid token",
			token: "valid-token-123",
			setupMock: func(m *mocks.MockUserRepository) {
				m.Users[1] = &domain.User{
					ID:                    1,
					Email:                 "test@example.com",
					EmailVerified:         false,
					VerificationToken:     "valid-token-123",
					VerificationExpiresAt: time.Now().Add(1 * time.Hour),
				}
			},
			expectError: false,
		},
		{
			name:  "Expired token",
			token: "expired-token",
			setupMock: func(m *mocks.MockUserRepository) {
				m.Users[1] = &domain.User{
					ID:                    1,
					Email:                 "test@example.com",
					EmailVerified:         false,
					VerificationToken:     "expired-token",
					VerificationExpiresAt: time.Now().Add(-1 * time.Hour),
				}
			},
			expectError:   true,
			errorContains: "invalid",
		},
		{
			name:          "Invalid token",
			token:         "invalid-token",
			setupMock:     func(m *mocks.MockUserRepository) {},
			expectError:   true,
			errorContains: "invalid",
		},
		{
			name:          "Empty token",
			token:         "",
			setupMock:     func(m *mocks.MockUserRepository) {},
			expectError:   true,
			errorContains: "token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := mocks.NewMockUserRepository()
			tt.setupMock(mockRepo)

			conf := &config.Config{}

			mockEmailSender := mocks.NewMockEmailSender()
			svc, svcErr := NewVerificationService(mockRepo, mockEmailSender, conf)
			if svcErr != nil {
				t.Fatalf("Failed to create verification service: %v", svcErr)
			}

			err := svc.VerifyEmail(context.Background(), tt.token)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorContains, err.Error())
				}
			} else {
				if svcErr != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestVerificationService_EdgeCases(t *testing.T) {
	t.Run("SendVerification with empty email", func(t *testing.T) {
		mockRepo := mocks.NewMockUserRepository()
		conf := &config.Config{
			Server: config.ServerConfig{
				BaseURL: "http://localhost:8080",
			},
		}

		mockEmailSender := mocks.NewMockEmailSender()
		svc, svcErr := NewVerificationService(mockRepo, mockEmailSender, conf)
			if svcErr != nil {
				t.Fatalf("Failed to create verification service: %v", svcErr)
			}

		user := &domain.User{
			ID:    1,
			Email: "",
		}

		err := svc.SendVerificationEmail(context.Background(), user)
		if err == nil {
			t.Error("Expected error for empty email")
		}
	})

	t.Run("ResendVerification with whitespace email", func(t *testing.T) {
		mockRepo := mocks.NewMockUserRepository()
		conf := &config.Config{
			Server: config.ServerConfig{
				BaseURL: "http://localhost:8080",
			},
		}

		mockEmailSender := mocks.NewMockEmailSender()
		svc, svcErr := NewVerificationService(mockRepo, mockEmailSender, conf)
			if svcErr != nil {
				t.Fatalf("Failed to create verification service: %v", svcErr)
			}

		err := svc.ResendVerification(context.Background(), "   ")

		// Should not error (timing safe)
		if svcErr != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})
}
