package mocks

import (
	"context"
	"errors"
	"time"

	"github.com/Olprog59/go-authstarter/internal/ports"
	"github.com/Olprog59/go-authstarter/internal/domain"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrEmailAlreadyExists = errors.New("email already registered")
)

// passwordResetData stores password reset token information separate from User
type passwordResetData struct {
	Token     string
	ExpiresAt time.Time
}

// MockUserRepository is a mock implementation of ports.UserRepository for testing
type MockUserRepository struct {
	// Mock data storage
	Users       map[int64]*domain.User
	ResetTokens map[string]int64             // token -> userID mapping
	ResetData   map[int64]*passwordResetData // userID -> reset data

	// Mock behavior flags
	CreateError          error
	GetByIDError         error
	GetByEmailError      error
	DeleteError          error
	UpdateRoleError      error
	LockAccountError     error
	IncrementFailedError error
	ResetFailedError     error
	UpdatePasswordError  error
	ClearResetTokenError error
	ListError            error

	// Call tracking
	CreateCalls          int
	GetByIDCalls         int
	GetByEmailCalls      int
	DeleteCalls          int
	UpdateRoleCalls      int
	LockAccountCalls     int
	IncrementFailedCalls int
	ResetFailedCalls     int
}

// NewMockUserRepository creates a new mock user repository
func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{
		Users:       make(map[int64]*domain.User),
		ResetTokens: make(map[string]int64),
		ResetData:   make(map[int64]*passwordResetData),
	}
}

func (m *MockUserRepository) Create(ctx context.Context, email, password string) (*domain.User, error) {
	m.CreateCalls++
	if m.CreateError != nil {
		return nil, m.CreateError
	}

	// Check if email already exists
	for _, user := range m.Users {
		if user.Email == email {
			return nil, ErrEmailAlreadyExists
		}
	}

	id := int64(len(m.Users) + 1)
	user := &domain.User{
		ID:       id,
		Email:    email,
		Password: password,
		Role:     domain.RoleUser,
	}
	m.Users[id] = user
	return user, nil
}

func (m *MockUserRepository) GetByID(ctx context.Context, id int64) (*domain.User, error) {
	m.GetByIDCalls++
	if m.GetByIDError != nil {
		return nil, m.GetByIDError
	}

	user, exists := m.Users[id]
	if !exists {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (m *MockUserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	m.GetByEmailCalls++
	if m.GetByEmailError != nil {
		return nil, m.GetByEmailError
	}

	for _, user := range m.Users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, ErrUserNotFound
}

func (m *MockUserRepository) Delete(ctx context.Context, id int64) error {
	m.DeleteCalls++
	if m.DeleteError != nil {
		return m.DeleteError
	}

	delete(m.Users, id)
	return nil
}

func (m *MockUserRepository) UpdateRole(ctx context.Context, userID int64, role string) error {
	m.UpdateRoleCalls++
	if m.UpdateRoleError != nil {
		return m.UpdateRoleError
	}

	user, exists := m.Users[userID]
	if !exists {
		return ErrUserNotFound
	}
	user.Role = domain.UserRole(role)
	return nil
}

func (m *MockUserRepository) LockAccount(ctx context.Context, userID int64, until time.Time) error {
	m.LockAccountCalls++
	if m.LockAccountError != nil {
		return m.LockAccountError
	}

	user, exists := m.Users[userID]
	if !exists {
		return ErrUserNotFound
	}
	user.LockedUntil = &until
	return nil
}

func (m *MockUserRepository) IncrementFailedAttempts(ctx context.Context, userID int64) error {
	m.IncrementFailedCalls++
	if m.IncrementFailedError != nil {
		return m.IncrementFailedError
	}

	user, exists := m.Users[userID]
	if !exists {
		return ErrUserNotFound
	}
	user.FailedLoginAttempts++
	return nil
}

func (m *MockUserRepository) ResetFailedAttempts(ctx context.Context, userID int64) error {
	m.ResetFailedCalls++
	if m.ResetFailedError != nil {
		return m.ResetFailedError
	}

	user, exists := m.Users[userID]
	if !exists {
		return ErrUserNotFound
	}
	user.FailedLoginAttempts = 0
	return nil
}

func (m *MockUserRepository) List(ctx context.Context, offset, limit int) ([]*domain.User, int, error) {
	if m.ListError != nil {
		return nil, 0, m.ListError
	}

	// Get all users as a slice
	allUsers := make([]*domain.User, 0, len(m.Users))
	for _, user := range m.Users {
		allUsers = append(allUsers, user)
	}

	totalCount := len(allUsers)

	// Apply pagination
	if offset >= totalCount {
		return []*domain.User{}, totalCount, nil
	}

	end := min(offset+limit, totalCount)

	paginatedUsers := allUsers[offset:end]
	return paginatedUsers, totalCount, nil
}

func (m *MockUserRepository) UpdatePassword(ctx context.Context, userID int64, hashedPassword string) error {
	if m.UpdatePasswordError != nil {
		return m.UpdatePasswordError
	}

	user, exists := m.Users[userID]
	if !exists {
		return ErrUserNotFound
	}
	user.Password = hashedPassword
	return nil
}

func (m *MockUserRepository) SetPasswordResetToken(ctx context.Context, email, token string, expiresAt time.Time) error {
	user, err := m.GetByEmail(ctx, email)
	if err != nil {
		return err
	}
	m.ResetData[user.ID] = &passwordResetData{
		Token:     token,
		ExpiresAt: expiresAt,
	}
	m.ResetTokens[token] = user.ID
	return nil
}

func (m *MockUserRepository) GetByPasswordResetToken(ctx context.Context, token string) (*domain.User, error) {
	userID, exists := m.ResetTokens[token]
	if !exists {
		return nil, ErrUserNotFound
	}

	resetData, exists := m.ResetData[userID]
	if !exists || time.Now().After(resetData.ExpiresAt) {
		return nil, ErrUserNotFound
	}

	user, exists := m.Users[userID]
	if !exists {
		return nil, ErrUserNotFound
	}

	return user, nil
}

func (m *MockUserRepository) ClearPasswordResetToken(ctx context.Context, userID int64) error {
	if m.ClearResetTokenError != nil {
		return m.ClearResetTokenError
	}

	_, exists := m.Users[userID]
	if !exists {
		return ErrUserNotFound
	}

	// Remove reset data
	if resetData, exists := m.ResetData[userID]; exists {
		delete(m.ResetTokens, resetData.Token)
		delete(m.ResetData, userID)
	}
	return nil
}

func (m *MockUserRepository) UpdateDBSendEmail(ctx context.Context, token string, expiresAt time.Time, userID int64) error {
	user, exists := m.Users[userID]
	if !exists {
		return ErrUserNotFound
	}
	user.VerificationToken = token
	user.VerificationExpiresAt = expiresAt
	return nil
}

func (m *MockUserRepository) UpdateDBVerify(ctx context.Context, token string) error {
	for _, user := range m.Users {
		if user.VerificationToken == token && time.Now().Before(user.VerificationExpiresAt) {
			user.EmailVerified = true
			user.VerificationToken = ""
			return nil
		}
	}
	return ErrUserNotFound
}

func (m *MockUserRepository) GetPermissionsForRole(ctx context.Context, role string) ([]domain.Permission, error) {
	return nil, nil
}

func (m *MockUserRepository) AddPermissionToRole(ctx context.Context, role string, permission domain.Permission) error {
	return nil
}

func (m *MockUserRepository) RemovePermissionFromRole(ctx context.Context, role string, permission domain.Permission) error {
	return nil
}

func (m *MockUserRepository) CountUsers(ctx context.Context) (int, error) {
	return len(m.Users), nil
}

func (m *MockUserRepository) UserHasPermission(ctx context.Context, userID int64, permission domain.Permission) (bool, error) {
	return false, nil
}

// WithTx returns the same mock instance for transaction support in tests.
// In tests, we don't need real transactions, so we just return the mock itself.
func (m *MockUserRepository) WithTx(dbtx ports.DBTX) ports.AccountSecurityRepository {
	return m
}
