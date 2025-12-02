package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Olprog59/go-authstarter/internal/config"
	"github.com/Olprog59/go-authstarter/internal/domain"
	"github.com/Olprog59/go-authstarter/internal/ports"
	"github.com/Olprog59/go-authstarter/internal/service/auth"
	"golang.org/x/crypto/bcrypt"
)

// AuthService handles authentication operations / Gère les opérations d'authentification
type AuthService struct {
	userReader   ports.UserReader
	security     ports.AccountSecurityRepository
	refreshStore ports.RefreshTokenStore
	conf         *config.Config
	db           *sql.DB
	userLocks    map[int64]*lockEntry
	mapMutex     sync.Mutex
	metrics      AuthMetricsRecorder
}

// AuthMetricsRecorder records auth metrics / Enregistre les métriques d'authentification
type AuthMetricsRecorder interface {
	RecordAccountLockout()
}

// NewAuthService creates authentication service instance / Crée une instance de service d'authentification
func NewAuthService(
	repo ports.UserRepository,
	refreshStore ports.RefreshTokenStore,
	conf *config.Config,
	db *sql.DB,
	metrics AuthMetricsRecorder,
) *AuthService {
	svc := &AuthService{
		userReader:   repo,
		security:     repo,
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

// getUserLock retrieves or creates user-specific mutex / Récupère ou crée un mutex utilisateur
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

// cleanupInactiveLocks periodically removes unused locks / Nettoie périodiquement les locks inutilisés
func (s *AuthService) cleanupInactiveLocks() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.mapMutex.Lock()
		now := time.Now()
		for userID, entry := range s.userLocks {
			// Remove locks unused for more than 15 minutes / Supprime les locks inutilisés depuis plus de 15min
			if now.Sub(entry.lastUsed) > 15*time.Minute {
				delete(s.userLocks, userID)
			}
		}
		s.mapMutex.Unlock()
	}
}

// Login authenticates user and generates tokens / Authentifie l'utilisateur et génère les tokens
func (s *AuthService) Login(ctx context.Context, email, password, ipHash, uaHash string) (*domain.User, *auth.TokenPair, error) {

	// Retrieve user from database
	user, err := s.userReader.GetByEmail(ctx, email)
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
			if err := s.security.LockAccount(ctx, user.ID, lockedUntil); err != nil {
				slog.Error("failed to lock account", "user_id", user.ID, "err", err)
			}
			s.metrics.RecordAccountLockout()
			return nil, nil, fmt.Errorf("account locked due to multiple failed login attempts. Try again in %s", formatLockoutDuration(s.conf.Security.LockoutDuration))
		}

		// Update failed attempts count
		if err := s.security.IncrementFailedAttempts(ctx, user.ID); err != nil {
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

	// Start database transaction for atomic updates
	// IMPORTANT: Transaction starts BEFORE password check to include security updates
	tx, err := s.db.Begin()
	if err != nil {
		slog.Error("failed to start transaction for login", "err", err)
		return nil, nil, errors.New("internal server error")
	}
	defer tx.Rollback() // Ensure rollback on error

	// Create transaction-aware security and refresh token repositories
	txSecurityRepo := s.security.WithTx(tx)
	txRefreshStore := s.refreshStore.WithTx(tx)

	// Revoke ALL existing refresh tokens for this user (security measure)
	if err := txRefreshStore.RevokeAllForUser(ctx, user.ID); err != nil {
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
	if err := txRefreshStore.Save(ctx, refreshToken); err != nil {
		slog.Error("failed to save refresh token", "err", err)
		return nil, nil, errors.New("internal server error")
	}

	// Reset failed login attempts on successful login
	if err := txSecurityRepo.ResetFailedAttempts(ctx, user.ID); err != nil {
		slog.Error("failed to reset failed login attempts", "user_id", user.ID, "err", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		slog.Error("failed to commit login transaction", "err", err)
		return nil, nil, errors.New("internal server error")
	}

	return user, tokenPair, nil
}

// RefreshToken validates and rotates refresh token / Valide et renouvelle le refresh token
func (s *AuthService) RefreshToken(ctx context.Context, refreshToken, ipHash, uaHash string) (*auth.TokenPair, error) {

	// Retrieve token record from database
	tokenRecord, err := s.refreshStore.Get(ctx, refreshToken)
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
	user, err := s.userReader.GetByID(ctx, tokenRecord.UserID)
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
	if err := txRefreshStore.Revoke(ctx, refreshToken); err != nil {
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
	if err := txRefreshStore.Save(ctx, newRefreshToken); err != nil {
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

// ValidateCredentials checks if credentials are valid / Vérifie si les identifiants sont valides
func (s *AuthService) ValidateCredentials(ctx context.Context, email, password string) (*domain.User, error) {
	user, err := s.userReader.GetByEmail(ctx, email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}

// RevokeAllTokens revokes all refresh tokens for a user / Révoque tous les refresh tokens d'un utilisateur
func (s *AuthService) RevokeAllTokens(ctx context.Context, userID int64) error {
	// Acquire user-specific lock to prevent race conditions
	lock := s.getUserLock(userID)
	lock.Lock()
	defer lock.Unlock()

	// Revoke all tokens for this user with context / Révoque tous les tokens avec contexte
	if err := s.refreshStore.RevokeAllForUser(ctx, userID); err != nil {
		slog.Error("failed to revoke tokens", "err", err, "user_id", userID)
		return errors.New("internal server error")
	}

	slog.Info("all refresh tokens revoked", "user_id", userID)
	return nil
}
