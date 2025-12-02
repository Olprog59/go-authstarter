package service

import (
	"fmt"
	"net/mail"
	"strings"
	"sync"
	"time"
	"unicode"
)

// isStrongPassword validates that a password meets security requirements:
//   - At least 8 characters long
//   - Maximum 72 bytes (bcrypt limitation)
//   - Contains at least one uppercase letter
//   - Contains at least one lowercase letter
//   - Contains at least one digit
//   - Contains at least one special character
//
// Returns true if the password meets all requirements.
func isStrongPassword(password string) bool {
	// Check length constraints
	if len(password) < 8 {
		return false
	}

	// bcrypt has a maximum password length of 72 bytes
	if len([]byte(password)) > 72 {
		return false
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasDigit && hasSpecial
}

// isValidEmail validates an email address format.
// It checks:
//   - Valid RFC 5322 format using net/mail.ParseAddress
//   - Maximum length of 254 characters (RFC 5321)
//   - Non-empty string
//
// Returns true if the email is valid.
func isValidEmail(email string) bool {
	if email == "" || len(email) > 254 {
		return false
	}

	// Trim whitespace
	email = strings.TrimSpace(email)

	// Use standard library to validate email format
	_, err := mail.ParseAddress(email)
	return err == nil
}

// lockEntry tracks a user-specific mutex and its last access time for cleanup.
// This is used to prevent race conditions during concurrent operations while
// avoiding memory leaks by tracking when locks were last used.
type lockEntry struct {
	mu       *sync.Mutex
	lastUsed time.Time
}

// formatLockoutDuration formats a duration into a human-readable string.
// Examples: "1 minute", "15 minutes", "45 seconds"
func formatLockoutDuration(d time.Duration) string {
	// Check if duration is less than 1 minute
	if d < time.Minute {
		seconds := int(d.Seconds())
		if seconds == 1 {
			return "1 second"
		}
		return fmt.Sprintf("%d seconds", seconds)
	}

	// Duration is >= 1 minute
	minutes := int(d.Round(time.Minute).Minutes())
	if minutes == 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", minutes)
}
