package service

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Olprog59/go-fun/internal/config"
	"github.com/Olprog59/go-fun/internal/domain"
	"github.com/Olprog59/go-fun/internal/ports"
	"github.com/Olprog59/go-fun/internal/service/auth"
	"golang.org/x/crypto/bcrypt"
)

// AuthService handles authentication operations including login, token refresh,
// and credential validation. It follows the Single Responsibility Principle
// by focusing solely on authentication concerns.
type AuthService struct {
	repo         ports.UserRepository
	refreshStore ports.RefreshTokenStore
	conf         *config.Config
	db           *sql.DB
	userLocks    map[int64]*lockEntry
	mapMutex     sync.Mutex
	metrics      AuthMetricsRecorder
}

// AuthMetricsRecorder defines the interface for recording authentication-related metrics.
type AuthMetricsRecorder interface {
	RecordAccountLockout()
}

// NewAuthService creates a new authentication service instance.
func NewAuthService(
	repo ports.UserRepository,
	refreshStore ports.RefreshTokenStore,
	conf *config.Config,
	db *sql.DB,
	metrics AuthMetricsRecorder,
) *AuthService {
	svc := &AuthService{
		repo:         repo,
		refreshStore: refreshStore,
		conf:         conf,
		db:           db,
		userLocks:    make(map[int64]*lockEntry),
		metrics:      metrics,
	}

	// Start background cleanup of inactive locks
	go svc.cleanupInactiveLocks()

	return svc
}

// getUserLock retrieves or creates a user-specific mutex for concurrency control.
// This prevents race conditions during concurrent authentication operations for the same user.
func (s *AuthService) getUserLock(userID int64) *sync.Mutex {
	s.mapMutex.Lock()
	defer s.mapMutex.Unlock()

	entry, exists := s.userLocks[userID]
	if !exists {
		entry = &lockEntry{
			mu:       &sync.Mutex{},
			lastUsed: time.Now(),
		}
		s.userLocks[userID] = entry
	} else {
		entry.lastUsed = time.Now()
	}

	return entry.mu
}

// cleanupInactiveLocks periodically removes locks for users who haven't authenticated recently.
// This prevents memory leaks in long-running applications.
func (s *AuthService) cleanupInactiveLocks() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		s.mapMutex.Lock()
		now := time.Now()
		for userID, entry := range s.userLocks {
			// Remove locks unused for more than 2 hours
			if now.Sub(entry.lastUsed) > 2*time.Hour {
				delete(s.userLocks, userID)
			}
		}
		s.mapMutex.Unlock()
	}
}

// Login authenticates a user with email and password, then generates access and refresh tokens.
// It implements comprehensive security measures:
//   - Email verification requirement
//   - Account lockout after failed attempts
//   - Token rotation (revokes all previous tokens)
//   - Client binding (IP and User-Agent hashing)
//   - User-specific locking to prevent race conditions
//
// Parameters:
//   - email: User's email address
//   - password: Plain-text password
//   - ipHash: SHA-256 hash of client IP
//   - uaHash: SHA-256 hash of User-Agent
//
// Returns:
//   - User object, token pair, and error (if any)
func (s *AuthService) Login(email, password, ipHash, uaHash string) (*domain.User, *auth.TokenPair, error) {
	// Retrieve user from database
	user, err := s.repo.GetByEmail(email)
	if err != nil {
		return nil, nil, ErrInvalidCredentials
	}

	// Check if account is locked
	if user.IsLocked() {
		lockDuration := time.Until(*user.LockedUntil)
		s.metrics.RecordAccountLockout()
		return nil, nil, fmt.Errorf("account locked due to multiple failed login attempts. Try again in %s", formatLockoutDuration(lockDuration))
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		// Increment failed attempts
		newFailedAttempts := user.FailedLoginAttempts + 1

		// Lock account if max attempts reached
		if newFailedAttempts >= s.conf.Security.MaxFailedAttempts {
			lockedUntil := time.Now().Add(s.conf.Security.LockoutDuration)
			if err := s.repo.LockAccount(user.ID, lockedUntil); err != nil {
				slog.Error("failed to lock account", "user_id", user.ID, "err", err)
			}
			s.metrics.RecordAccountLockout()
			return nil, nil, fmt.Errorf("account locked due to multiple failed login attempts. Try again in %s", formatLockoutDuration(s.conf.Security.LockoutDuration))
		}

		// Update failed attempts count
		if err := s.repo.IncrementFailedAttempts(user.ID); err != nil {
			slog.Error("failed to record failed login attempt", "user_id", user.ID, "err", err)
		}

		return nil, nil, ErrInvalidCredentials
	}

	// Check if email is verified
	if !user.EmailVerified {
		return nil, nil, errors.New("email not verified")
	}

	// Get user-specific lock to prevent race conditions
	userLock := s.getUserLock(user.ID)
	userLock.Lock()
	defer userLock.Unlock()

	// Start database transaction for atomic token rotation
	tx, err := s.db.Begin()
	if err != nil {
		slog.Error("failed to start transaction for login", "err", err)
		return nil, nil, errors.New("internal server error")
	}
	defer tx.Rollback()

	// Get transaction-aware refresh token store
	txRefreshStore := s.refreshStore.WithTx(tx)

	// Revoke ALL existing refresh tokens for this user (security measure)
	if err := txRefreshStore.RevokeAllForUser(user.ID); err != nil {
		slog.Error("failed to revoke user tokens during login", "err", err)
		return nil, nil, errors.New("internal server error")
	}

	// Generate new token pair
	tokenPair, err := auth.GenerateTokenPair(
		user.ID,
		string(user.Role),
		s.conf.Auth.JWTSecret,
		s.conf.Auth.AccessTokenDuration,
		s.conf.Auth.RefreshTokenDuration,
	)
	if err != nil {
		slog.Error("failed to generate token pair", "err", err)
		return nil, nil, errors.New("internal server error")
	}

	// Save new refresh token with client binding
	refreshToken := &domain.RefreshToken{
		Token:     tokenPair.RefreshToken,
		UserID:    user.ID,
		IssueAt:   time.Now(),
		ExpiresAt: time.Now().Add(s.conf.Auth.RefreshTokenDuration),
		IsRevoked: false,
		IPHash:    ipHash,
		UAHash:    uaHash,
	}
	if err := txRefreshStore.Save(refreshToken); err != nil {
		slog.Error("failed to save refresh token", "err", err)
		return nil, nil, errors.New("internal server error")
	}

	// Reset failed login attempts on successful login
	if err := s.repo.ResetFailedAttempts(user.ID); err != nil {
		slog.Error("failed to reset failed login attempts", "user_id", user.ID, "err", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		slog.Error("failed to commit login transaction", "err", err)
		return nil, nil, errors.New("internal server error")
	}

	return user, tokenPair, nil
}

// RefreshToken validates a refresh token and issues a new token pair.
// It implements token rotation for enhanced security:
//   - Validates token exists and is not revoked
//   - Checks expiration
//   - Verifies client binding (IP and User-Agent)
//   - Revokes old token before issuing new one (atomic operation)
//   - Uses transaction to ensure atomicity
//
// Parameters:
//   - refreshToken: The current refresh token
//   - ipHash: SHA-256 hash of current client IP
//   - uaHash: SHA-256 hash of current User-Agent
//
// Returns:
//   - New token pair and error (if any)
func (s *AuthService) RefreshToken(refreshToken, ipHash, uaHash string) (*auth.TokenPair, error) {
	// Retrieve token record from database
	tokenRecord, err := s.refreshStore.Get(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Security checks
	if tokenRecord.IsRevoked {
		return nil, errors.New("revoked refresh token")
	}

	if time.Now().After(tokenRecord.ExpiresAt) {
		return nil, errors.New("expired refresh token")
	}

	// Verify client binding (IP and User-Agent)
	if tokenRecord.IPHash != ipHash || tokenRecord.UAHash != uaHash {
		slog.Warn("refresh token binding validation failed",
			"user_id", tokenRecord.UserID,
			"expected_ip", tokenRecord.IPHash,
			"got_ip", ipHash,
			"expected_ua", tokenRecord.UAHash,
			"got_ua", uaHash,
		)
		return nil, errors.New("refresh token binding validation failed")
	}

	// Get user to include role in new token
	user, err := s.repo.GetByID(tokenRecord.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Get user-specific lock to prevent race conditions
	userLock := s.getUserLock(user.ID)
	userLock.Lock()
	defer userLock.Unlock()

	// Start database transaction for atomic token rotation
	tx, err := s.db.Begin()
	if err != nil {
		slog.Error("failed to start transaction for token refresh", "err", err)
		return nil, errors.New("internal server error")
	}
	defer tx.Rollback()

	// Get transaction-aware refresh token store
	txRefreshStore := s.refreshStore.WithTx(tx)

	// Revoke the old refresh token (token rotation)
	if err := txRefreshStore.Revoke(refreshToken); err != nil {
		slog.Error("failed to revoke old refresh token", "err", err)
		return nil, errors.New("internal server error")
	}

	// Generate a new token pair
	newTokenPair, err := auth.GenerateTokenPair(
		user.ID,
		string(user.Role),
		s.conf.Auth.JWTSecret,
		s.conf.Auth.AccessTokenDuration,
		s.conf.Auth.RefreshTokenDuration,
	)
	if err != nil {
		slog.Error("failed to generate new token pair", "err", err)
		return nil, errors.New("internal server error")
	}

	// Save the new refresh token with same client binding
	newRefreshToken := &domain.RefreshToken{
		Token:     newTokenPair.RefreshToken,
		UserID:    user.ID,
		IssueAt:   time.Now(),
		ExpiresAt: time.Now().Add(s.conf.Auth.RefreshTokenDuration),
		IsRevoked: false,
		IPHash:    ipHash,
		UAHash:    uaHash,
	}
	if err := txRefreshStore.Save(newRefreshToken); err != nil {
		slog.Error("failed to save new refresh token", "err", err)
		return nil, errors.New("internal server error")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		slog.Error("failed to commit token refresh transaction", "err", err)
		return nil, errors.New("internal server error")
	}

	return newTokenPair, nil
}

// ValidateCredentials checks if the provided email and password are valid.
// This is a simpler alternative to Login when you only need credential validation
// without token generation.
//
// Returns:
//   - User object and error (if any)
func (s *AuthService) ValidateCredentials(email, password string) (*domain.User, error) {
	user, err := s.repo.GetByEmail(email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}
