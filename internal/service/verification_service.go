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
//
// Following ISP (Interface Segregation Principle), VerificationService now depends
// on specific interfaces it needs rather than the monolithic UserRepository.
//
// Following DIP (Dependency Inversion Principle), VerificationService depends on
// the EmailSender interface rather than the concrete EmailService implementation.
type VerificationService struct {
	verification ports.EmailVerificationRepository
	userReader   ports.UserReader
	emailSender  ports.EmailSender
	conf         *config.Config
	template     *template.Template
}

// NewVerificationService creates a new email verification service instance.
// Returns error if template parsing fails / Retourne une erreur si le parsing du template échoue
func NewVerificationService(
	repo ports.UserRepository,
	emailSender ports.EmailSender,
	conf *config.Config,
) (*VerificationService, error) {
	// Parse email verification template
	tmpl, err := template.ParseFS(verificationTemplateFS, "templates/verification_email.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse verification email template: %w", err)
	}

	return &VerificationService{
		verification: repo,
		userReader:   repo,
		emailSender:  emailSender,
		conf:         conf,
		template:     tmpl,
	}, nil
}

// SendVerificationEmail generates a verification token and sends email / Génère un token et envoie l'email de vérification
func (s *VerificationService) SendVerificationEmail(ctx context.Context, user *domain.User) error {
	// Generate a unique verification token
	verificationToken := uuid.New().String()
	expiresAt := time.Now().Add(24 * time.Hour)

	// Store the token in the database with context / Stocke le token avec propagation du contexte
	if err := s.verification.UpdateDBSendEmail(ctx, verificationToken, expiresAt, user.ID); err != nil {
		slog.Error("failed to set verification token", "email", user.Email, "err", err)
		return fmt.Errorf("failed to generate verification token")
	}

	// Send the verification email asynchronously
	go s.sendVerificationEmailAsync(user.Email, verificationToken)

	return nil
}

// sendVerificationEmailAsync sends the verification email in a goroutine.
// This prevents blocking the registration request and improves response times.
// Uses a 30-second timeout to prevent goroutine leaks from hanging email sends.
func (s *VerificationService) sendVerificationEmailAsync(email, token string) {
	// Create context with timeout to prevent goroutine leaks
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Construct verification URL
	verificationURL := fmt.Sprintf("%s/verify?token=%s", s.conf.Server.BaseURL, token)

	// Prepare template data
	data := struct {
		Email           string
		VerificationURL string
		Duration        string
	}{
		Email:           email,
		VerificationURL: verificationURL,
		Duration:        "24 heures",
	}

	// Render email template
	var body bytes.Buffer
	if err := s.template.Execute(&body, data); err != nil {
		slog.Error("failed to render verification email template", "err", err)
		return
	}

	// Send email with timeout
	subject := "Verify Your Email Address"
	err := s.emailSender.Send(ctx, email, subject, body.String())
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			slog.Error("verification email send timed out", "email", email, "timeout", "30s")
		} else {
			slog.Error("failed to send verification email", "email", email, "err", err)
		}
	} else {
		slog.Info("verification email sent successfully", "email", email)
	}
}

// ResendVerification resends verification email (timing-safe) / Renvoie l'email de vérification (sécurisé contre l'énumération)
func (s *VerificationService) ResendVerification(ctx context.Context, email string) error {
	// Validate email format
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

	// If already verified, don't send email (but don't reveal this info)
	if user.EmailVerified {
		time.Sleep(200 * time.Millisecond)
		return nil
	}

	// Generate new verification token
	verificationToken := uuid.New().String()
	expiresAt := time.Now().Add(24 * time.Hour)

	// Store the new token with context / Stocke le token avec contexte
	if err := s.verification.UpdateDBSendEmail(ctx, verificationToken, expiresAt, user.ID); err != nil {
		slog.Error("failed to set verification token for resend", "email", email, "err", err)
		return nil
	}

	// Send verification email asynchronously
	go s.sendVerificationEmailAsync(email, verificationToken)

	return nil
}

// VerifyEmail verifies a user's email using token / Vérifie l'email d'un utilisateur via le token
func (s *VerificationService) VerifyEmail(ctx context.Context, token string) error {
	if token == "" {
		return fmt.Errorf("verification token is required")
	}

	// Verify the token and update user's email_verified status with context
	if err := s.verification.UpdateDBVerify(ctx, token); err != nil {
		return fmt.Errorf("invalid or expired verification token")
	}

	return nil
}
