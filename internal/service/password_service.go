package service

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"time"

	"github.com/Olprog59/go-authstarter/internal/config"
	"github.com/Olprog59/go-authstarter/internal/domain"
	"github.com/Olprog59/go-authstarter/internal/ports"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/password_reset_email.html
var passwordResetTemplateFS embed.FS

// PasswordService handles password operations / Gère les opérations de mot de passe
type PasswordService struct {
	userReader   ports.UserReader
	passwordRepo ports.PasswordResetRepository
	refreshStore ports.RefreshTokenStore
	emailSender  ports.EmailSender
	conf         *config.Config
	template     *template.Template
}

// NewPasswordService creates a new password management service instance.
// Returns error if template parsing fails / Retourne une erreur si le parsing du template échoue
func NewPasswordService(
	repo ports.UserRepository,
	refreshStore ports.RefreshTokenStore,
	emailSender ports.EmailSender,
	conf *config.Config,
) (*PasswordService, error) {
	// Parse password reset email template
	tmpl, err := template.ParseFS(passwordResetTemplateFS, "templates/password_reset_email.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse password reset template: %w", err)
	}

	return &PasswordService{
		userReader:   repo,
		passwordRepo: repo,
		refreshStore: refreshStore,
		emailSender:  emailSender,
		conf:         conf,
		template:     tmpl,
	}, nil
}

// RequestPasswordReset initiates password reset (timing-safe) / Démarre la réinitialisation du mot de passe (sécurisé)
func (s *PasswordService) RequestPasswordReset(ctx context.Context, email string) error {
	// Validate email format first
	if !isValidEmail(email) {
		time.Sleep(200 * time.Millisecond)
		return nil
	}

	// Try to get user by email with context / Récupère l'utilisateur avec contexte
	user, err := s.userReader.GetByEmail(ctx, email)
	if err != nil {
		time.Sleep(200 * time.Millisecond)
		return nil
	}

	// Check if a valid token already exists
	if user.PasswordResetToken.Valid && user.PasswordResetExpiresAt.Valid && time.Now().Before(user.PasswordResetExpiresAt.Time) {
		return nil
	}

	// Generate a secure random reset token
	resetToken := uuid.New().String()
	expiresAt := time.Now().Add(1 * time.Hour)

	// Store reset token in database with context / Stocke le token avec contexte
	err = s.passwordRepo.SetPasswordResetToken(ctx, email, resetToken, expiresAt)
	if err != nil {
		slog.Error("failed to set password reset token", "email", email, "err", err)
		return nil
	}

	// Send password reset email asynchronously
	go s.sendPasswordResetEmailAsync(user, resetToken)

	return nil
}

// sendPasswordResetEmailAsync sends password reset email async / Envoie l'email de réinitialisation de façon asynchrone
func (s *PasswordService) sendPasswordResetEmailAsync(user *domain.User, resetToken string) {
	// Create context with timeout to prevent goroutine leaks
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Construct reset URL
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.conf.Server.FrontendURL, resetToken)

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

	// Send email with timeout
	subject := "Reset Your Password"
	err := s.emailSender.Send(ctx, user.Email, subject, body.String())
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			slog.Error("password reset email send timed out", "email", user.Email, "timeout", "30s")
		} else {
			slog.Error("failed to send password reset email", "email", user.Email, "err", err)
		}
	}
}

// ResetPassword completes password reset using token / Finalise la réinitialisation du mot de passe via token
func (s *PasswordService) ResetPassword(ctx context.Context, token, newPassword string) error {
	// Validate inputs
	if token == "" {
		return fmt.Errorf("reset token is required")
	}

	if !isStrongPassword(newPassword) {
		return fmt.Errorf("password does not meet strength requirements: must be at least 8 characters with uppercase, lowercase, digit, and special character")
	}

	// Get user by reset token with context / Récupère l'utilisateur avec contexte
	user, err := s.passwordRepo.GetByPasswordResetToken(ctx, token)
	if err != nil {
		return fmt.Errorf("invalid or expired reset token")
	}

	// Hash the new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.conf.Security.BcryptCost)
	if err != nil {
		slog.Error("failed to hash password", "err", err)
		return fmt.Errorf("failed to process password")
	}

	// Update password in database with context / Met à jour le mot de passe avec contexte
	if err := s.passwordRepo.UpdatePassword(ctx, user.ID, string(hashedPassword)); err != nil {
		slog.Error("failed to update password", "user_id", user.ID, "err", err)
		return fmt.Errorf("failed to update password")
	}

	// Clear the reset token (prevent reuse)
	if err := s.passwordRepo.ClearPasswordResetToken(ctx, user.ID); err != nil {
		slog.Error("failed to clear password reset token", "user_id", user.ID, "err", err)
	}

	// Revoke all refresh tokens to force re-login
	if err := s.refreshStore.RevokeAllForUser(ctx, user.ID); err != nil {
		slog.Error("failed to revoke refresh tokens after password reset", "user_id", user.ID, "err", err)
	}

	return nil
}

// ChangePassword allows password change with current password verification / Permet le changement de mot de passe avec vérification
func (s *PasswordService) ChangePassword(ctx context.Context, userID int64, currentPassword, newPassword string) error {
	// Get user from database with context / Récupère l'utilisateur avec contexte
	user, err := s.userReader.GetByID(ctx, userID)
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

	// Prevent password reuse
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(newPassword)); err == nil {
		return fmt.Errorf("new password must be different from current password")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.conf.Security.BcryptCost)
	if err != nil {
		slog.Error("failed to hash new password", "err", err)
		return fmt.Errorf("failed to process password")
	}

	// Update password with context / Met à jour le mot de passe avec contexte
	if err := s.passwordRepo.UpdatePassword(ctx, userID, string(hashedPassword)); err != nil {
		slog.Error("failed to update password", "user_id", userID, "err", err)
		return fmt.Errorf("failed to update password")
	}

	// Revoke all refresh tokens to force re-login
	if err := s.refreshStore.RevokeAllForUser(ctx, userID); err != nil {
		slog.Error("failed to revoke refresh tokens after password change", "user_id", userID, "err", err)
	}

	return nil
}
