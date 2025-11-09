package service

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/Olprog59/go-fun/internal/config"
	"github.com/Olprog59/go-fun/internal/domain"
	"github.com/Olprog59/go-fun/internal/ports"
	"github.com/Olprog59/go-fun/internal/repository"
	"github.com/Olprog59/go-fun/internal/service/auth"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

//go:embed templates/*.html
var templatesFS embed.FS

type UserService struct {
	repo          ports.UserRepository
	refreshStore  ports.RefreshTokenStore
	conf          *config.Config
	emailSvc      *EmailService
	userLocks     map[int64]*sync.Mutex
	mapMutex      sync.Mutex
	db            *sql.DB
	emailTemplate *template.Template
}

// NewUserService creates and returns a new UserService instance.
// It initializes the service with all its dependencies, including the user repository,
// configuration, refresh token store, and database connection.
//
// This constructor also performs critical setup tasks:
// 1.  It parses the HTML email templates required for sending verification emails. If the
//     templates cannot be parsed, it panics because the application cannot function
//     correctly without them.
// 2.  It initializes a map to manage user-specific mutexes, which are used to prevent
//     race conditions during concurrent operations like login or token revocation.
//
// Parameters:
//   - repo: An implementation of the UserRepository port for database access.
//   - conf: The application's configuration settings.
//   - refreshStore: An implementation of the RefreshTokenStore port for managing refresh tokens.
//   - db: A direct database connection, used for managing transactions.
//
// Returns:
//   A pointer to a fully initialized UserService.
func NewUserService(repo ports.UserRepository, conf *config.Config, refreshStore ports.RefreshTokenStore, db *sql.DB) *UserService {
	tmpl, err := template.ParseFS(templatesFS, "templates/verification_email.html")
	if err != nil {
		panic(fmt.Sprintf("Failed to parse email template: %v", err))
	}

	return &UserService{
		repo:          repo,
		conf:          conf,
		refreshStore:  refreshStore,
		emailSvc:      NewEmailService(conf),
		userLocks:     make(map[int64]*sync.Mutex),
		db:            db,
		emailTemplate: tmpl,
	}
}

// getUserLock retrieves a mutex for a specific user ID.
// This function ensures that any operation that needs to be atomic for a given user
// (e.g., revoking old tokens and issuing new ones) can be safely executed concurrently
// without race conditions.
//
// It uses a map of mutexes, where each key is a user ID. A global mutex (`mapMutex`)
// protects the map itself from concurrent read/write access. If a mutex for a given
// user ID does not exist, it is created on-the-fly.
//
// This lazy-initialization approach is memory-efficient as it only creates mutexes
// for users who are actively performing sensitive operations.
func (s *UserService) getUserLock(userID int64) *sync.Mutex {
	s.mapMutex.Lock()
	defer s.mapMutex.Unlock()

	if _, ok := s.userLocks[userID]; !ok {
		s.userLocks[userID] = &sync.Mutex{}
	}

	return s.userLocks[userID]
}

// Auth verifies a user's credentials.
// It retrieves a user by their email and compares the provided password with the stored hash.
//
// This function enforces two important security checks:
// 1.  It returns `ErrInvalidCredentials` for both non-existent users and incorrect passwords
//     to prevent email enumeration attacks.
// 2.  It checks if the user's email has been verified. If not, it returns an error,
//     preventing unverified users from authenticating.
//
// Parameters:
//   - email: The user's email address.
//   - password: The plain-text password to verify.
//
// Returns:
//   - A pointer to the authenticated `domain.User` on success.
//   - An error if authentication fails, which could be `ErrInvalidCredentials` or
//     a specific error for unverified emails.
func (s *UserService) Auth(email, password string) (*domain.User, error) {
	u, err := s.repo.GetByEmail(email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if !u.EmailVerified {
		return nil, errors.New("email not verified")
	}

	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)) != nil {
		return nil, ErrInvalidCredentials
	}

	return u, nil
}

// encode generates a bcrypt hash of a password.
// It uses a default cost of 10, which is a reasonable balance between security and performance.
// Bcrypt is used because it is a slow, adaptive hashing function, making it resistant
// to brute-force attacks.
func (s *UserService) encode(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), 10)
}

// Register creates a new user account, validates the input, and sends a verification email.
//
// The registration process includes several steps:
// 1.  Validates that the email address has a valid format.
// 2.  Enforces a strong password policy (minimum length, character types).
// 3.  Checks if the email is already registered to prevent duplicates.
// 4.  Hashes the password using bcrypt before storing it.
// 5.  Creates the user record in the database.
// 6.  Generates a unique verification token and sends it to the user's email asynchronously.
//
// Parameters:
//   - email: The email address for the new account.
//   - password: The plain-text password for the new account.
//
// Returns:
//   - A pointer to the newly created `domain.User` on success.
//   - An error if validation fails or if a database error occurs.
func (s *UserService) Register(email, password string) (*domain.User, error) {
	if !isValidEmail(email) {
		return nil, errors.New("invalid email format")
	}
	if !isStrongPassword(password) {
		return nil, errors.New("password must be ≥8 chars with upper, lower, digit, special")
	}

	if _, err := s.repo.GetByEmail(email); err == nil {
		return nil, errors.New("email already registered")
	} else if !errors.Is(err, ports.ErrNotFound) && !errors.Is(err, repository.ErrNoRecord) {
		return nil, err
	}

	bpass, err := s.encode(password)
	if err != nil {
		return nil, err
	}
	user, err := s.repo.Create(email, string(bpass))
	if err != nil {
		return nil, err
	}

	err = s.SendVerificationEmail(user)
	if err != nil {
		return nil, err
	}

	log.Println(user.VerificationToken)

	s.sendVerificationEmailAsync(user.Email, user.VerificationToken)

	return user, nil
}

// Login handles the user authentication process and session creation.
//
// This function orchestrates the entire login flow:
// 1.  It first authenticates the user by verifying their email and password. It also ensures
//     the user's email is already verified.
// 2.  To prevent race conditions, it acquires a user-specific lock before modifying token data.
// 3.  It operates within a database transaction to ensure atomicity. If any step fails,
//     the entire transaction is rolled back.
// 4.  As a security measure, it revokes all existing refresh tokens for the user, ensuring
//     that a new login invalidates all other sessions.
// 5.  It generates a new pair of tokens (access and refresh).
// 6.  The new refresh token is saved to the database, associated with a hash of the client's
//     IP address and User-Agent to bind the token to a specific client.
// 7.  If all steps succeed, the transaction is committed.
//
// Parameters:
//   - email: The user's email address.
//   - password: The user's plain-text password.
//   - ipHash: A SHA-256 hash of the client's IP address.
//   - uaHash: A SHA-256 hash of the client's User-Agent string.
//
// Returns:
//   - A pointer to the authenticated `domain.User`.
//   - A pointer to the new `auth.TokenPair`.
//   - An error if authentication or any step in the process fails.
func (s *UserService) Login(email, password, ipHash, uaHash string) (*domain.User, *auth.TokenPair, error) {
	user, err := s.repo.GetByEmail(email)
	if err != nil {
		return nil, nil, ErrInvalidCredentials
	}

	if !user.EmailVerified {
		return nil, nil, errors.New("email not verified")
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, nil, ErrInvalidCredentials
	}

	mu := s.getUserLock(user.ID)
	mu.Lock()
	defer mu.Unlock()

	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		} else if err != nil {
			_ = tx.Rollback()
		}
	}()

	txStore := s.refreshStore.WithTx(tx)

	if err = txStore.RevokeAllForUser(user.ID); err != nil {
		return nil, nil, fmt.Errorf("failed to revoke old tokens: %w", err)
	}

	tokenPair, err := auth.GenerateTokenPair(user.ID, s.conf.Auth.JWTSecret, s.conf.Auth.AccessTokenDuration, s.conf.Auth.RefreshTokenDuration)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	now := time.Now()
	rt := &domain.RefreshToken{
		Token:     tokenPair.RefreshToken,
		UserID:    user.ID,
		IssueAt:   now,
		ExpiresAt: now.Add(s.conf.Auth.RefreshTokenDuration),
		IsRevoked: false,
		IPHash:    ipHash,
		UAHash:    uaHash,
	}

	if err = txStore.Save(rt); err != nil {
		return nil, nil, fmt.Errorf("failed to save new token: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	user.Token = rt
	return user, tokenPair, nil
}

// GetUser retrieves a single user by their unique ID.
// It acts as a simple proxy to the user repository.
// If the user is not found, it returns a `ErrUserNotFound` error.
func (s *UserService) GetUser(id int64) (*domain.User, error) {
	user, err := s.repo.GetByID(id)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// ListUsers retrieves a list of all users from the repository.
// This is a simple proxy method to the repository's `List` function.
func (s *UserService) ListUsers() ([]*domain.User, error) {
	return s.repo.List()
}

// RefreshToken handles the process of issuing a new token pair using a valid refresh token.
// This mechanism, known as token rotation, is critical for security.
//
// The process is as follows:
// 1.  The provided refresh token is retrieved from the database.
// 2.  It is validated to ensure it is not revoked or expired.
// 3.  The old refresh token is immediately revoked to prevent replay attacks. If this step
//     fails, the process is aborted.
// 4.  A new pair of access and refresh tokens is generated.
// 5.  The new refresh token is saved to the database, associated with the client's
//     IP and User-Agent hashes for improved security.
//
// Parameters:
//   - refreshToken: The refresh token string provided by the client.
//   - ipHash: A SHA-256 hash of the client's IP address.
//   - uaHash: A SHA-256 hash of the client's User-Agent string.
//
// Returns:
//   - A pointer to the new `auth.TokenPair` on success.
//   - An error if the token is invalid, expired, or if any database operation fails.
func (s *UserService) RefreshToken(refreshToken, ipHash, uaHash string) (*auth.TokenPair, error) {

	storedToken, err := s.refreshStore.Get(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid or missing refresh token")
	}

	if storedToken.IsRevoked || time.Now().After(storedToken.ExpiresAt) {
		return nil, fmt.Errorf("expired or revoked refresh token")
	}

	userID := storedToken.UserID

	if err = s.refreshStore.Revoke(refreshToken); err != nil {
		return nil, fmt.Errorf("failed to revoke refresh token")
	}

	tokenPair, err := auth.GenerateTokenPair(userID, s.conf.Auth.JWTSecret, s.conf.Auth.AccessTokenDuration, s.conf.Auth.RefreshTokenDuration)
	if err != nil {
		return nil, fmt.Errorf("could not generate token")
	}

	now := time.Now()
	newRefreshToken := &domain.RefreshToken{
		Token:     tokenPair.RefreshToken,
		UserID:    userID,
		IssueAt:   now,
		ExpiresAt: now.Add(s.conf.Auth.RefreshTokenDuration),
		IsRevoked: false,
		IPHash:    ipHash,
		UAHash:    uaHash,
	}

	if err := s.refreshStore.Save(newRefreshToken); err != nil {
		return nil, fmt.Errorf("could not save new refresh token")
	}

	return tokenPair, nil
}

// SendVerificationEmail generates a new verification token, associates it with the user,
// and updates the user's record in the database.
//
// This function is responsible for the first part of the email verification process:
// 1.  A new, unique verification token (UUID) is generated.
// 2.  The token's expiration time is calculated based on the application configuration.
// 3.  The user's database record is updated with the new token and its expiration date.
//
// This function does NOT send the email itself; it only prepares the user's data.
// The actual email sending is handled by `sendVerificationEmailAsync` to avoid
// blocking the main execution flow.
func (s *UserService) SendVerificationEmail(user *domain.User) error {
	token := uuid.New().String()
	expiresAt := time.Now().Add(s.conf.EmailVerification.TokenExpiration)

	err := s.repo.UpdateDBSendEmail(token, expiresAt, user.ID)
	if err != nil {
		return nil
	}

	user.VerificationToken = token
	user.VerificationExpiresAt = expiresAt

	return nil
}

// isValidEmail checks if the provided string is a valid email address format.
// It uses the standard library's `net/mail.ParseAddress` for robust validation
// and also checks that the email length does not exceed the standard limit of 254 characters.
func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil && len(email) <= 254
}

// isStrongPassword checks if a password meets the application's security policy.
// The policy requires the password to be at least 8 characters long and contain at least
// one of each of the following: an uppercase letter, a lowercase letter, a digit, and a
// special character from a predefined set.
func isStrongPassword(pw string) bool {
	if len(pw) < 8 {
		return false
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	special := "!@#$%^&*()_+-=[]{}|;:,.<>?"
	for _, r := range pw {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case strings.ContainsRune(special, r):
			hasSpecial = true
		}
	}
	return hasUpper && hasLower && hasDigit && hasSpecial
}

// ResendVerification handles the logic for resending a verification email.
// This function is designed with security in mind to prevent leaking information.
//
// Key behaviors:
// 1.  **Timing-Safe**: If the email does not exist in the database, the function
//     introduces a small, artificial delay and returns `nil`. This prevents attackers
//     from using response times to guess whether an email is registered (email enumeration).
// 2.  **Idempotent for Verified Users**: If the user's email is already verified,
//     it returns `nil` silently, treating the request as a success without taking action.
// 3.  **Token Freshness**: It checks if an existing, unexpired token is "fresh" (i.e.,
//     was generated recently, within 20% of its total lifetime). If so, it resends the
//     same token to avoid generating unnecessary new ones.
// 4.  **Token Regeneration**: If no fresh token exists, it generates a new verification
//     token, updates the database, and triggers the asynchronous email sending.
// 5.  **Error Obfuscation**: In case of a database error during token update, it logs
//     the error but returns `nil` to the caller, maintaining the timing-safe behavior.
func (s *UserService) ResendVerification(email string) error {

	if !isValidEmail(email) {
		return errors.New("invalid email format")
	}

	user, err := s.repo.GetByEmail(email)
	if err != nil {

		time.Sleep(200 * time.Millisecond)
		return nil
	}

	if user.EmailVerified {
		return nil
	}

	tokenAge := time.Since(user.VerificationExpiresAt.Add(-s.conf.EmailVerification.TokenExpiration))
	tokenFreshnessThreshold := s.conf.EmailVerification.TokenExpiration * 20 / 100

	if user.VerificationToken != "" &&
		tokenAge < tokenFreshnessThreshold &&
		time.Now().Before(user.VerificationExpiresAt) {

		s.sendVerificationEmailAsync(user.Email, user.VerificationToken)
		return nil
	}

	token := uuid.New().String()
	expiresAt := time.Now().Add(s.conf.EmailVerification.TokenExpiration)

	if err := s.repo.UpdateDBSendEmail(token, expiresAt, user.ID); err != nil {
		slog.Error("Failed to update verification token", "err", err)
		return nil
	}

	s.sendVerificationEmailAsync(email, token)

	return nil
}

// sendVerificationEmailAsync sends a verification email to a user in a separate goroutine.
// This asynchronous approach ensures that the user-facing operation (like registration)
// is not blocked by the time it takes to send an email.
//
// The function performs these steps in the background:
// 1.  Constructs the full verification link using the base URL from the configuration.
// 2.  Populates an HTML template with the user's email, the verification link, and the
//     token's validity duration.
// 3.  Sends the composed email using the `EmailService`.
// 4.  Logs any errors that occur during template execution or email sending.
// 5.  In a development environment, it logs the verification link directly for easy testing.
func (s *UserService) sendVerificationEmailAsync(email, token string) {
	go func() {
		link := fmt.Sprintf("%s/verify?token=%s", s.conf.Server.BaseURL, token)

		data := struct {
			Email      string
			VerifyLink string
			Duration   string
		}{
			Email:      email,
			VerifyLink: link,
			Duration:   formatDurationEN(s.conf.EmailVerification.TokenExpiration),
		}

		// Render template
		var body bytes.Buffer
		if err := s.emailTemplate.Execute(&body, data); err != nil {
			slog.Error("Failed to execute email template", "err", err)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := s.emailSvc.Send(ctx, email, "Verify your account", body.String()); err != nil {
			slog.Error("Email verification send failed", "email", email, "err", err)
			return
		}

		if s.conf.Environment == "development" {
			slog.Info("📧 Verification link (dev)", "email", email, "link", link)
		}
	}()
}

// formatDurationEN formats a time.Duration into a human-readable English string.
// It breaks down the duration into hours and minutes, providing a more user-friendly
// representation than the default `time.Duration` string format.
//
// Examples:
//   - 25 * time.Hour + 30 * time.Minute -> "25 hours and 30 minutes"
//   - 2 * time.Hour -> "2 hours"
//   - 45 * time.Minute -> "45 minutes"
//   - 30 * time.Second -> "30 seconds"
func formatDurationEN(d time.Duration) string {
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60

	if hours > 0 && minutes > 0 {
		return fmt.Sprintf("%d hour%s and %d minute%s",
			hours, plural(hours), minutes, plural(minutes))
	}
	if hours > 0 {
		return fmt.Sprintf("%d hour%s", hours, plural(hours))
	}
	if minutes > 0 {
		return fmt.Sprintf("%d minute%s", minutes, plural(minutes))
	}

	// Less than a minute
	seconds := int(d.Seconds())
	return fmt.Sprintf("%d second%s", seconds, plural(seconds))
}

// plural returns "s" if the input number is greater than 1, otherwise it returns an empty string.
// This is a simple helper function used for correct grammatical formatting in English.
func plural(n int) string {
	if n > 1 {
		return "s"
	}
	return ""
}
