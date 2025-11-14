package service

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"time"

	"github.com/Olprog59/go-fun/internal/config"
	"github.com/Olprog59/go-fun/internal/domain"
	"github.com/Olprog59/go-fun/internal/ports"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/password_reset_email.html
var passwordResetTemplateFS embed.FS

// PasswordService handles password-related operations including reset requests,
// password changes, and validation. It follows the Single Responsibility Principle.
type PasswordService struct {
	repo         ports.UserRepository
	refreshStore ports.RefreshTokenStore
	emailSvc     *EmailService
	conf         *config.Config
	template     *template.Template
}

// NewPasswordService creates a new password management service instance.
func NewPasswordService(
	repo ports.UserRepository,
	refreshStore ports.RefreshTokenStore,
	conf *config.Config,
) *PasswordService {
	// Parse password reset email template
	tmpl, err := template.ParseFS(passwordResetTemplateFS, "templates/password_reset_email.html")
	if err != nil {
		panic(fmt.Sprintf("Failed to parse password reset template: %v", err))
	}

	return &PasswordService{
		repo:         repo,
		refreshStore: refreshStore,
		emailSvc:     NewEmailService(conf),
		conf:         conf,
		template:     tmpl,
	}
}

// RequestPasswordReset initiates the password reset process for a user.
// This function is timing-safe to prevent email enumeration attacks:
//   - Always returns success, even if email doesn't exist
//   - Uses consistent response time via sleep for non-existent emails
//   - Sends reset email asynchronously
//
// The reset token is valid for 1 hour and can only be used once.
//
// Parameters:
//   - email: The email address to send the reset link to
//
// Returns:
//   - Always returns nil (timing-safe)
func (s *PasswordService) RequestPasswordReset(email string) error {
	// Validate email format first (fail fast for invalid format)
	if !isValidEmail(email) {
		// Sleep to prevent timing attacks
		time.Sleep(200 * time.Millisecond)
		return nil
	}

	// Try to get user by email
	user, err := s.repo.GetByEmail(email)
	if err != nil {
		// User doesn't exist - sleep to match successful case timing
		time.Sleep(200 * time.Millisecond)
		return nil
	}

	// Generate a secure random reset token
	resetToken := uuid.New().String()
	expiresAt := time.Now().Add(1 * time.Hour)

	// Store reset token in database
	err = s.repo.SetPasswordResetToken(email, resetToken, expiresAt)
	if err != nil {
		slog.Error("failed to set password reset token", "email", email, "err", err)
		// Still return nil to prevent email enumeration
		return nil
	}

	// Send password reset email asynchronously (don't block the request)
	go s.sendPasswordResetEmailAsync(user, resetToken)

	return nil
}

// sendPasswordResetEmailAsync sends the password reset email in a goroutine.
// This ensures consistent response times and prevents timing-based user enumeration.
func (s *PasswordService) sendPasswordResetEmailAsync(user *domain.User, resetToken string) {
	// Construct reset URL
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.conf.Server.BaseURL, resetToken)

	// Prepare template data
	data := struct {
		Email    string
		ResetURL string
	}{
		Email:    user.Email,
		ResetURL: resetURL,
	}

	// Render email template
	var body bytes.Buffer
	if err := s.template.Execute(&body, data); err != nil {
		slog.Error("failed to render password reset email template", "err", err)
		return
	}

	// Send email
	subject := "Reset Your Password"
	err := s.emailSvc.Send(context.Background(), user.Email, subject, body.String())
	if err != nil {
		slog.Error("failed to send password reset email", "email", user.Email, "err", err)
	}
}

// ResetPassword completes the password reset process using a valid reset token.
// Security features:
//   - Validates token existence and expiration
//   - Enforces password strength requirements
//   - Clears reset token after use (one-time use)
//   - Revokes all refresh tokens to force re-login
//
// Parameters:
//   - token: The password reset token from the email link
//   - newPassword: The new password to set
//
// Returns:
//   - Error if token is invalid, expired, or password is weak
func (s *PasswordService) ResetPassword(token, newPassword string) error {
	// Validate inputs
	if token == "" {
		return fmt.Errorf("reset token is required")
	}

	if !isStrongPassword(newPassword) {
		return fmt.Errorf("password does not meet strength requirements: must be at least 8 characters with uppercase, lowercase, digit, and special character")
	}

	// Get user by reset token
	user, err := s.repo.GetByPasswordResetToken(token)
	if err != nil {
		return fmt.Errorf("invalid or expired reset token")
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.conf.Security.BcryptCost)
	if err != nil {
		slog.Error("failed to hash password", "err", err)
		return fmt.Errorf("failed to process password")
	}

	// Update password in database
	if err := s.repo.UpdatePassword(user.ID, string(hashedPassword)); err != nil {
		slog.Error("failed to update password", "user_id", user.ID, "err", err)
		return fmt.Errorf("failed to update password")
	}

	// Clear the reset token (prevent reuse)
	if err := s.repo.ClearPasswordResetToken(user.ID); err != nil {
		slog.Error("failed to clear password reset token", "user_id", user.ID, "err", err)
		// Don't fail the request - password was already changed
	}

	// Revoke all refresh tokens to force re-login with new password
	if err := s.refreshStore.RevokeAllForUser(user.ID); err != nil {
		slog.Error("failed to revoke refresh tokens after password reset", "user_id", user.ID, "err", err)
		// Don't fail the request - password was already changed
	}

	return nil
}

// ChangePassword allows an authenticated user to change their password.
// This requires the current password for verification.
//
// Parameters:
//   - userID: The ID of the user changing their password
//   - currentPassword: The current password for verification
//   - newPassword: The new password to set
//
// Returns:
//   - Error if current password is incorrect or new password is weak
func (s *PasswordService) ChangePassword(userID int64, currentPassword, newPassword string) error {
	// Get user from database
	user, err := s.repo.GetByID(userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(currentPassword)); err != nil {
		return fmt.Errorf("current password is incorrect")
	}

	// Validate new password strength
	if !isStrongPassword(newPassword) {
		return fmt.Errorf("new password does not meet strength requirements")
	}

	// Prevent password reuse (check if same as current)
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(newPassword)); err == nil {
		return fmt.Errorf("new password must be different from current password")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.conf.Security.BcryptCost)
	if err != nil {
		slog.Error("failed to hash new password", "err", err)
		return fmt.Errorf("failed to process password")
	}

	// Update password
	if err := s.repo.UpdatePassword(userID, string(hashedPassword)); err != nil {
		slog.Error("failed to update password", "user_id", userID, "err", err)
		return fmt.Errorf("failed to update password")
	}

	// Revoke all refresh tokens to force re-login
	if err := s.refreshStore.RevokeAllForUser(userID); err != nil {
		slog.Error("failed to revoke refresh tokens after password change", "user_id", userID, "err", err)
		// Don't fail - password was already changed
	}

	return nil
}
