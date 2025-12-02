package mocks

import (
	"context"
	"database/sql"
	"time"

	"github.com/Olprog59/go-authstarter/internal/domain"
	"github.com/Olprog59/go-authstarter/internal/ports"
)

// MockRefreshTokenStore is a mock implementation of ports.RefreshTokenStore for testing
type MockRefreshTokenStore struct {
	// Mock data storage
	Tokens map[string]*domain.RefreshToken

	// Mock behavior flags
	SaveError           error
	GetError            error
	RevokeError         error
	RevokeAllError      error
	PurgeExpiredError   error

	// Call tracking
	SaveCalls      int
	GetCalls       int
	RevokeCalls    int
	RevokeAllCalls int
	PurgeCalls     int
}

// NewMockRefreshTokenStore creates a new mock refresh token store
func NewMockRefreshTokenStore() *MockRefreshTokenStore {
	return &MockRefreshTokenStore{
		Tokens: make(map[string]*domain.RefreshToken),
	}
}

func (m *MockRefreshTokenStore) Save(ctx context.Context, token *domain.RefreshToken) error {
	m.SaveCalls++
	if m.SaveError != nil {
		return m.SaveError
	}

	m.Tokens[token.Token] = token
	return nil
}

func (m *MockRefreshTokenStore) Get(ctx context.Context, tokenString string) (*domain.RefreshToken, error) {
	m.GetCalls++
	if m.GetError != nil {
		return nil, m.GetError
	}

	token, exists := m.Tokens[tokenString]
	if !exists {
		return nil, ports.ErrNotFound
	}
	return token, nil
}

func (m *MockRefreshTokenStore) Revoke(ctx context.Context, tokenString string) error {
	m.RevokeCalls++
	if m.RevokeError != nil {
		return m.RevokeError
	}

	token, exists := m.Tokens[tokenString]
	if !exists {
		return ports.ErrNotFound
	}
	token.IsRevoked = true
	return nil
}

func (m *MockRefreshTokenStore) RevokeAllForUser(ctx context.Context, userID int64) error {
	m.RevokeAllCalls++
	if m.RevokeAllError != nil {
		return m.RevokeAllError
	}

	for _, token := range m.Tokens {
		if token.UserID == userID {
			token.IsRevoked = true
		}
	}
	return nil
}

func (m *MockRefreshTokenStore) PurgeExpired(ctx context.Context, before time.Time) error {
	m.PurgeCalls++
	if m.PurgeExpiredError != nil {
		return m.PurgeExpiredError
	}

	for key, token := range m.Tokens {
		if token.ExpiresAt.Before(before) {
			delete(m.Tokens, key)
		}
	}
	return nil
}

func (m *MockRefreshTokenStore) WithTx(tx *sql.Tx) ports.RefreshTokenStore {
	// For testing, return the same mock
	return m
}
