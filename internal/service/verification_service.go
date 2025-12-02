package service

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"sync"
	"time"

	"github.com/Olprog59/go-authstarter/internal/config"
	"github.com/Olprog59/go-authstarter/internal/domain"
	"github.com/Olprog59/go-authstarter/internal/ports"
	"github.com/google/uuid"
)

//go:embed templates/verification_email.html
var verificationTemplateFS embed.FS

// resendAttempt tracks resend attempts for throttling / Suivi des tentatives de renvoi pour le throttling
type resendAttempt struct {
	count     int       // Number of attempts / Nombre de tentatives
	firstSeen time.Time // First attempt timestamp / Horodatage de la première tentative
	lastSeen  time.Time // Last attempt timestamp / Horodatage de la dernière tentative
}

// VerificationService handles email verification / Gère la vérification des emails
type VerificationService struct {
	verification    ports.EmailVerificationRepository
	userReader      ports.UserReader
	emailSender     ports.EmailSender
	conf            *config.Config
	template        *template.Template
	resendThrottle  map[string]*resendAttempt // email -> attempt tracking
	throttleMutex   sync.RWMutex              // Protects resendThrottle map
	cleanupInterval time.Duration             // How often to clean expired entries
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

	svc := &VerificationService{
		verification:    repo,
		userReader:      repo,
		emailSender:     emailSender,
		conf:            conf,
		template:        tmpl,
		resendThrottle:  make(map[string]*resendAttempt),
		cleanupInterval: 10 * time.Minute, // Clean expired entries every 10 minutes
	}

	// Start background cleanup goroutine
	go svc.cleanupExpiredThrottles()

	return svc, nil
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

// sendVerificationEmailAsync sends verification email async / Envoie l'email de vérification de façon asynchrone
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

	// Check throttling FIRST to prevent database queries for throttled requests
	// This prevents abuse even if email doesn't exist
	if !s.checkResendThrottle(email) {
		// Still sleep to maintain timing-safe behavior
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
	expiresAt := time.Now().Add(s.conf.EmailVerification.TokenExpiration)

	// Store the new token with context / Stocke le token avec contexte
	if err := s.verification.UpdateDBSendEmail(ctx, verificationToken, expiresAt, user.ID); err != nil {
		slog.Error("failed to set verification token for resend", "email", email, "err", err)
		return nil
	}

	// Send verification email asynchronously
	go s.sendVerificationEmailAsync(email, verificationToken)

	slog.Info("verification email resend successful", "email", email)

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

// checkResendThrottle checks if email resend is allowed for this email address
// Returns true if allowed, false if throttled / Vérifie si le renvoi est autorisé
func (s *VerificationService) checkResendThrottle(email string) bool {
	s.throttleMutex.Lock()
	defer s.throttleMutex.Unlock()

	now := time.Now()
	attempt, exists := s.resendThrottle[email]

	// First request for this email - allow it
	if !exists {
		s.resendThrottle[email] = &resendAttempt{
			count:     1,
			firstSeen: now,
			lastSeen:  now,
		}
		return true
	}

	// Check if cooldown period has passed since first attempt
	cooldownExpired := now.Sub(attempt.firstSeen) >= s.conf.EmailVerification.ResendCooldown

	// If cooldown expired, reset the counter
	if cooldownExpired {
		s.resendThrottle[email] = &resendAttempt{
			count:     1,
			firstSeen: now,
			lastSeen:  now,
		}
		return true
	}

	// Within cooldown period - check if max attempts exceeded
	if attempt.count >= s.conf.EmailVerification.ResendMaxAttempts {
		// Log throttling event
		remainingTime := s.conf.EmailVerification.ResendCooldown - now.Sub(attempt.firstSeen)
		slog.Warn("email verification resend throttled",
			"email", email,
			"attempts", attempt.count,
			"remaining_cooldown", remainingTime.Round(time.Second).String(),
		)
		return false
	}

	// Increment attempt counter and update last seen
	attempt.count++
	attempt.lastSeen = now
	return true
}

// cleanupExpiredThrottles periodically removes expired throttle entries to prevent memory leaks
// Runs in a background goroutine / Nettoie périodiquement les entrées expirées
func (s *VerificationService) cleanupExpiredThrottles() {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		s.throttleMutex.Lock()

		now := time.Now()
		expiredEmails := []string{}

		// Find all expired entries
		for email, attempt := range s.resendThrottle {
			if now.Sub(attempt.lastSeen) >= s.conf.EmailVerification.ResendCooldown*2 {
				expiredEmails = append(expiredEmails, email)
			}
		}

		// Remove expired entries
		for _, email := range expiredEmails {
			delete(s.resendThrottle, email)
		}

		s.throttleMutex.Unlock()

		if len(expiredEmails) > 0 {
			slog.Debug("cleaned up expired resend throttle entries",
				"count", len(expiredEmails),
			)
		}
	}
}
