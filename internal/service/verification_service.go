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
)

//go:embed templates/verification_email.html
var verificationTemplateFS embed.FS

// VerificationService handles email verification operations.
// It follows the Single Responsibility Principle by focusing solely on
// email verification concerns.
type VerificationService struct {
	repo      ports.UserRepository
	emailSvc  *EmailService
	conf      *config.Config
	template  *template.Template
}

// NewVerificationService creates a new email verification service instance.
func NewVerificationService(
	repo ports.UserRepository,
	conf *config.Config,
) *VerificationService {
	// Parse email verification template
	tmpl, err := template.ParseFS(verificationTemplateFS, "templates/verification_email.html")
	if err != nil {
		panic(fmt.Sprintf("Failed to parse verification email template: %v", err))
	}

	return &VerificationService{
		repo:     repo,
		emailSvc: NewEmailService(conf),
		conf:     conf,
		template: tmpl,
	}
}

// SendVerificationEmail generates a verification token and sends a verification email.
// The token is valid for 24 hours.
//
// Parameters:
//   - user: The user to send the verification email to
//
// Returns:
//   - Error if email sending fails
func (s *VerificationService) SendVerificationEmail(user *domain.User) error {
	// Generate a unique verification token
	verificationToken := uuid.New().String()
	expiresAt := time.Now().Add(24 * time.Hour) // Token valid for 24 hours

	// Store the token in the database
	if err := s.repo.UpdateDBSendEmail(verificationToken, expiresAt, user.ID); err != nil {
		slog.Error("failed to set verification token", "email", user.Email, "err", err)
		return fmt.Errorf("failed to generate verification token")
	}

	// Send the verification email asynchronously
	go s.sendVerificationEmailAsync(user.Email, verificationToken)

	return nil
}

// sendVerificationEmailAsync sends the verification email in a goroutine.
// This prevents blocking the registration request and improves response times.
func (s *VerificationService) sendVerificationEmailAsync(email, token string) {
	// Construct verification URL
	verificationURL := fmt.Sprintf("%s/verify?token=%s", s.conf.Server.BaseURL, token)

	// Prepare template data
	data := struct {
		Email           string
		VerificationURL string
	}{
		Email:           email,
		VerificationURL: verificationURL,
	}

	// Render email template
	var body bytes.Buffer
	if err := s.template.Execute(&body, data); err != nil {
		slog.Error("failed to render verification email template", "err", err)
		return
	}

	// Send email
	subject := "Verify Your Email Address"
	err := s.emailSvc.Send(context.Background(), email, subject, body.String())
	if err != nil {
		slog.Error("failed to send verification email", "email", email, "err", err)
	} else {
		slog.Info("verification email sent successfully", "email", email)
	}
}

// ResendVerification resends the verification email to a user.
// This function is timing-safe to prevent email enumeration:
//   - Always returns success, even if email doesn't exist or is already verified
//   - Uses consistent response time
//
// Parameters:
//   - email: The email address to resend verification to
//
// Returns:
//   - Always returns nil (timing-safe)
func (s *VerificationService) ResendVerification(email string) error {
	// Validate email format
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

	// If already verified, don't send email (but don't reveal this info)
	if user.EmailVerified {
		time.Sleep(200 * time.Millisecond)
		return nil
	}

	// Generate new verification token
	verificationToken := uuid.New().String()
	expiresAt := time.Now().Add(24 * time.Hour)

	// Store the new token
	if err := s.repo.UpdateDBSendEmail(verificationToken, expiresAt, user.ID); err != nil {
		slog.Error("failed to set verification token for resend", "email", email, "err", err)
		// Still return nil to prevent enumeration
		return nil
	}

	// Send verification email asynchronously
	go s.sendVerificationEmailAsync(email, verificationToken)

	return nil
}

// VerifyEmail verifies a user's email using the provided token.
//
// Parameters:
//   - token: The verification token from the email link
//
// Returns:
//   - Error if token is invalid or expired
func (s *VerificationService) VerifyEmail(token string) error {
	if token == "" {
		return fmt.Errorf("verification token is required")
	}

	// Verify the token and update user's email_verified status
	if err := s.repo.UpdateDBVerify(token); err != nil {
		return fmt.Errorf("invalid or expired verification token")
	}

	return nil
}
