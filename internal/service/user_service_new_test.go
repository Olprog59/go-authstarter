package service

import (
	"context"
	"testing"

	"github.com/Olprog59/go-authstarter/internal/config"
	"github.com/Olprog59/go-authstarter/internal/domain"
	"github.com/Olprog59/go-authstarter/internal/mocks"
	"github.com/Olprog59/go-authstarter/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

func TestUserService_Register(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		password      string
		setupMock     func(*mocks.MockUserRepository)
		expectError   bool
		errorContains string
	}{
		{
			name:     "Valid registration",
			email:    "test@example.com",
			password: "ValidP@ss123",
			setupMock: func(m *mocks.MockUserRepository) {
				// No special setup needed
			},
			expectError: false,
		},
		{
			name:          "Invalid email format",
			email:         "invalid-email",
			password:      "ValidP@ss123",
			setupMock:     func(m *mocks.MockUserRepository) {},
			expectError:   true,
			errorContains: "invalid email",
		},
		{
			name:          "Weak password - too short",
			email:         "test@example.com",
			password:      "Weak1!",
			setupMock:     func(m *mocks.MockUserRepository) {},
			expectError:   true,
			errorContains: "strength requirements",
		},
		{
			name:          "Weak password - no uppercase",
			email:         "test@example.com",
			password:      "weakpass123!",
			setupMock:     func(m *mocks.MockUserRepository) {},
			expectError:   true,
			errorContains: "strength requirements",
		},
		{
			name:          "Weak password - no digit",
			email:         "test@example.com",
			password:      "WeakPass!",
			setupMock:     func(m *mocks.MockUserRepository) {},
			expectError:   true,
			errorContains: "strength requirements",
		},
		{
			name:          "Weak password - no special char",
			email:         "test@example.com",
			password:      "WeakPass123",
			setupMock:     func(m *mocks.MockUserRepository) {},
			expectError:   true,
			errorContains: "strength requirements",
		},
		{
			name:     "Email already exists",
			email:    "existing@example.com",
			password: "ValidP@ss123",
			setupMock: func(m *mocks.MockUserRepository) {
				// Use the standard repository error that the service checks for
				m.CreateError = repository.ErrDup
			},
			expectError:   true,
			errorContains: "already registered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := mocks.NewMockUserRepository()
			mockRefreshStore := mocks.NewMockRefreshTokenStore()
			tt.setupMock(mockRepo)

			conf := &config.Config{
				Security: config.SecurityConfig{
					BcryptCost: bcrypt.MinCost, // Use minimum cost for faster tests
				},
			}

			svc := NewUserService(mockRepo, mockRefreshStore, conf)
			user, err := svc.Register(context.Background(), tt.email, tt.password)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if user == nil {
					t.Error("Expected user to be created")
				} else {
					if user.Email != tt.email {
						t.Errorf("Expected email '%s', got '%s'", tt.email, user.Email)
					}
					if user.Role != domain.RoleUser {
						t.Errorf("Expected role 'user', got '%s'", user.Role)
					}
					// Verify password was hashed
					if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(tt.password)); err != nil {
						t.Error("Password was not properly hashed")
					}
				}
			}
		})
	}
}

func TestUserService_GetUser(t *testing.T) {
	tests := []struct {
		name          string
		userID        int64
		setupMock     func(*mocks.MockUserRepository)
		expectError   bool
		errorContains string
	}{
		{
			name:   "Get existing user",
			userID: 1,
			setupMock: func(m *mocks.MockUserRepository) {
				m.Users[1] = &domain.User{
					ID:    1,
					Email: "user@example.com",
					Role:  domain.RoleUser,
				}
			},
			expectError: false,
		},
		{
			name:          "Get non-existent user",
			userID:        999,
			setupMock:     func(m *mocks.MockUserRepository) {},
			expectError:   true,
			errorContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := mocks.NewMockUserRepository()
			mockRefreshStore := mocks.NewMockRefreshTokenStore()
			tt.setupMock(mockRepo)

			svc := NewUserService(mockRepo, mockRefreshStore, &config.Config{})
			user, err := svc.GetUser(context.Background(), tt.userID)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if user == nil {
					t.Error("Expected user to be returned")
				}
			}
		})
	}
}

func TestUserService_ListUsers(t *testing.T) {
	mockRepo := mocks.NewMockUserRepository()
	mockRefreshStore := mocks.NewMockRefreshTokenStore()

	// Add test users
	mockRepo.Users[1] = &domain.User{ID: 1, Email: "user1@example.com"}
	mockRepo.Users[2] = &domain.User{ID: 2, Email: "user2@example.com"}
	mockRepo.Users[3] = &domain.User{ID: 3, Email: "user3@example.com"}

	svc := NewUserService(mockRepo, mockRefreshStore, &config.Config{})

	// Test with pagination: get first 10 users
	users, totalCount, err := svc.ListUsers(context.Background(), 0, 10)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(users) != 3 {
		t.Errorf("Expected 3 users, got %d", len(users))
	}

	if totalCount != 3 {
		t.Errorf("Expected total count 3, got %d", totalCount)
	}
}

func TestUserService_DeleteUser(t *testing.T) {
	tests := []struct {
		name        string
		userID      int64
		setupMock   func(*mocks.MockUserRepository, *mocks.MockRefreshTokenStore)
		expectError bool
	}{
		{
			name:   "Delete existing user",
			userID: 1,
			setupMock: func(m *mocks.MockUserRepository, r *mocks.MockRefreshTokenStore) {
				m.Users[1] = &domain.User{ID: 1, Email: "user@example.com"}
			},
			expectError: false,
		},
		{
			name:        "Delete non-existent user",
			userID:      999,
			setupMock:   func(m *mocks.MockUserRepository, r *mocks.MockRefreshTokenStore) {},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := mocks.NewMockUserRepository()
			mockRefreshStore := mocks.NewMockRefreshTokenStore()
			tt.setupMock(mockRepo, mockRefreshStore)

			svc := NewUserService(mockRepo, mockRefreshStore, &config.Config{})
			err := svc.DeleteUser(context.Background(), tt.userID)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				// Verify user was deleted
				if _, exists := mockRepo.Users[tt.userID]; exists {
					t.Error("User was not deleted from repository")
				}
				// Verify tokens were revoked
				if mockRefreshStore.RevokeAllCalls != 1 {
					t.Errorf("Expected RevokeAllForUser to be called once, got %d", mockRefreshStore.RevokeAllCalls)
				}
			}
		})
	}
}

func TestUserService_UpdateUserRole(t *testing.T) {
	tests := []struct {
		name        string
		userID      int64
		newRole     domain.UserRole
		setupMock   func(*mocks.MockUserRepository)
		expectError bool
	}{
		{
			name:    "Update to moderator",
			userID:  1,
			newRole: domain.RoleModerator,
			setupMock: func(m *mocks.MockUserRepository) {
				m.Users[1] = &domain.User{ID: 1, Email: "user@example.com", Role: domain.RoleUser}
			},
			expectError: false,
		},
		{
			name:    "Update to admin",
			userID:  1,
			newRole: domain.RoleAdmin,
			setupMock: func(m *mocks.MockUserRepository) {
				m.Users[1] = &domain.User{ID: 1, Email: "user@example.com", Role: domain.RoleUser}
			},
			expectError: false,
		},
		{
			name:        "Update non-existent user",
			userID:      999,
			newRole:     domain.RoleAdmin,
			setupMock:   func(m *mocks.MockUserRepository) {},
			expectError: true,
		},
		{
			name:        "Invalid role",
			userID:      1,
			newRole:     domain.UserRole("invalid"),
			setupMock:   func(m *mocks.MockUserRepository) {},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := mocks.NewMockUserRepository()
			mockRefreshStore := mocks.NewMockRefreshTokenStore()
			tt.setupMock(mockRepo)

			svc := NewUserService(mockRepo, mockRefreshStore, &config.Config{})
			err := svc.UpdateUserRole(context.Background(), tt.userID, tt.newRole)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				// Verify role was updated
				user := mockRepo.Users[tt.userID]
				if user.Role != tt.newRole {
					t.Errorf("Expected role '%s', got '%s'", tt.newRole, user.Role)
				}
			}
		})
	}
}

