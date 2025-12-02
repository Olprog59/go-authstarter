package mocks

import (
	"context"
	"errors"

	"github.com/Olprog59/go-authstarter/internal/domain"
	"github.com/Olprog59/go-authstarter/internal/service/auth"
)

// Common mock errors
var (
	ErrMockUserNotFound      = errors.New("user not found")
	ErrMockInvalidCredentials = errors.New("invalid credentials")
	ErrMockEmailNotVerified  = errors.New("email not verified")
	ErrMockAccountLocked     = errors.New("account is locked")
	ErrMockTokenExpired      = errors.New("token expired")
	ErrMockTokenInvalid      = errors.New("token invalid")
	ErrMockBindingFailure    = errors.New("token binding validation failed")
)

// MockUserService is a mock implementation of UserService for testing
type MockUserService struct {
	// Mock data
	Users map[int64]*domain.User

	// Mock behavior
	RegisterFunc func(email, password string) (*domain.User, error)
	GetUserFunc  func(id int64) (*domain.User, error)

	// Call tracking
	RegisterCalls int
	GetUserCalls  int
}

func NewMockUserService() *MockUserService {
	return &MockUserService{
		Users: make(map[int64]*domain.User),
	}
}

func (m *MockUserService) Register(email, password string) (*domain.User, error) {
	m.RegisterCalls++
	if m.RegisterFunc != nil {
		return m.RegisterFunc(email, password)
	}
	// Default behavior
	return nil, errors.New("not implemented")
}

func (m *MockUserService) GetUser(id int64) (*domain.User, error) {
	m.GetUserCalls++
	if m.GetUserFunc != nil {
		return m.GetUserFunc(id)
	}
	// Default behavior
	if user, ok := m.Users[id]; ok {
		return user, nil
	}
	return nil, ErrMockUserNotFound
}

// MockAuthService is a mock implementation of AuthService for testing
type MockAuthService struct {
	// Mock behavior
	LoginFunc        func(email, password, ipHash, uaHash string) (*domain.User, *auth.TokenPair, error)
	RefreshTokenFunc func(refreshToken, ipHash, uaHash string) (*auth.TokenPair, error)

	// Call tracking
	LoginCalls        int
	RefreshTokenCalls int
}

func NewMockAuthService() *MockAuthService {
	return &MockAuthService{}
}

func (m *MockAuthService) Login(email, password, ipHash, uaHash string) (*domain.User, *auth.TokenPair, error) {
	m.LoginCalls++
	if m.LoginFunc != nil {
		return m.LoginFunc(email, password, ipHash, uaHash)
	}
	return nil, nil, errors.New("not implemented")
}

func (m *MockAuthService) RefreshToken(refreshToken, ipHash, uaHash string) (*auth.TokenPair, error) {
	m.RefreshTokenCalls++
	if m.RefreshTokenFunc != nil {
		return m.RefreshTokenFunc(refreshToken, ipHash, uaHash)
	}
	return nil, errors.New("not implemented")
}

// MockVerificationService is a mock implementation of VerificationService for testing
type MockVerificationService struct {
	// Mock behavior
	SendVerificationEmailFunc func(user *domain.User) error
	ResendVerificationFunc    func(email string) error
	VerifyEmailFunc           func(token string) error

	// Call tracking
	SendVerificationEmailCalls int
	ResendVerificationCalls    int
	VerifyEmailCalls           int
}

func NewMockVerificationService() *MockVerificationService {
	return &MockVerificationService{}
}

func (m *MockVerificationService) SendVerificationEmail(user *domain.User) error {
	m.SendVerificationEmailCalls++
	if m.SendVerificationEmailFunc != nil {
		return m.SendVerificationEmailFunc(user)
	}
	return nil // Default: success
}

func (m *MockVerificationService) ResendVerification(email string) error {
	m.ResendVerificationCalls++
	if m.ResendVerificationFunc != nil {
		return m.ResendVerificationFunc(email)
	}
	return nil // Default: success
}

func (m *MockVerificationService) VerifyEmail(token string) error {
	m.VerifyEmailCalls++
	if m.VerifyEmailFunc != nil {
		return m.VerifyEmailFunc(token)
	}
	return nil // Default: success
}

// MockPasswordService is a mock implementation of PasswordService for testing
type MockPasswordService struct {
	// Mock behavior
	RequestPasswordResetFunc func(email string) error
	ResetPasswordFunc        func(token, newPassword string) error

	// Call tracking
	RequestPasswordResetCalls int
	ResetPasswordCalls        int
}

func NewMockPasswordService() *MockPasswordService {
	return &MockPasswordService{}
}

func (m *MockPasswordService) RequestPasswordReset(email string) error {
	m.RequestPasswordResetCalls++
	if m.RequestPasswordResetFunc != nil {
		return m.RequestPasswordResetFunc(email)
	}
	return nil // Default: success (always returns nil for security)
}

func (m *MockPasswordService) ResetPassword(token, newPassword string) error {
	m.ResetPasswordCalls++
	if m.ResetPasswordFunc != nil {
		return m.ResetPasswordFunc(token, newPassword)
	}
	return nil // Default: success
}

// MockEmailSender is a mock implementation of EmailSender for testing
type MockEmailSender struct {
	// Mock behavior
	SendFunc func(ctx context.Context, to, subject, body string) error

	// Call tracking
	SendCalls int
	LastTo    string
	LastSubject string
	LastBody    string
}

func NewMockEmailSender() *MockEmailSender {
	return &MockEmailSender{}
}

func (m *MockEmailSender) Send(ctx context.Context, to, subject, body string) error {
	m.SendCalls++
	m.LastTo = to
	m.LastSubject = subject
	m.LastBody = body

	if m.SendFunc != nil {
		return m.SendFunc(ctx, to, subject, body)
	}
	return nil // Default: success
}
