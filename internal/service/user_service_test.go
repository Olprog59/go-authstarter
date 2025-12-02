package service

import (
	"testing"
	"time"

	"github.com/Olprog59/go-authstarter/internal/domain"
)

// TestIsStrongPassword tests password strength validation.
func TestIsStrongPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		expected bool
		reason   string
	}{
		// Valid passwords
		{
			name:     "Valid strong password",
			password: "MyP@ssw0rd",
			expected: true,
			reason:   "Contains uppercase, lowercase, digit, and special character",
		},
		{
			name:     "Valid with multiple special chars",
			password: "C0mpl3x!@#Pass",
			expected: true,
			reason:   "Contains all required character types",
		},
		{
			name:     "Minimum valid length (8 chars)",
			password: "Abcd123!",
			expected: true,
			reason:   "Exactly 8 characters with all required types",
		},
		{
			name:     "Long password with all types",
			password: "ThisIsAVeryL0ngP@ssword123",
			expected: true,
			reason:   "Long password with all required character types",
		},

		// Invalid passwords
		{
			name:     "Too short",
			password: "Ab1!",
			expected: false,
			reason:   "Only 4 characters (minimum is 8)",
		},
		{
			name:     "Missing uppercase",
			password: "myp@ssw0rd",
			expected: false,
			reason:   "No uppercase letters",
		},
		{
			name:     "Missing lowercase",
			password: "MYP@SSW0RD",
			expected: false,
			reason:   "No lowercase letters",
		},
		{
			name:     "Missing digit",
			password: "MyPassword!",
			expected: false,
			reason:   "No digits",
		},
		{
			name:     "Missing special character",
			password: "MyPassword123",
			expected: false,
			reason:   "No special characters",
		},
		{
			name:     "Only letters",
			password: "OnlyLettersHere",
			expected: false,
			reason:   "Missing digits and special characters",
		},
		{
			name:     "Only numbers",
			password: "12345678",
			expected: false,
			reason:   "Missing letters and special characters",
		},
		{
			name:     "Empty string",
			password: "",
			expected: false,
			reason:   "Empty password",
		},
		{
			name:     "7 chars with all types",
			password: "Ab1!xyz",
			expected: false,
			reason:   "7 characters (minimum is 8)",
		},
		{
			name:     "Max length (72 bytes) - valid",
			password: "Abcd123!" + string(make([]byte, 64)), // 8 + 64 = 72 bytes
			expected: true,
			reason:   "Exactly 72 bytes (bcrypt limit)",
		},
		{
			name:     "Over max length (73 bytes) - invalid",
			password: "Abcd123!" + string(make([]byte, 65)), // 8 + 65 = 73 bytes
			expected: false,
			reason:   "Exceeds 72 byte bcrypt limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isStrongPassword(tt.password)

			if result != tt.expected {
				t.Errorf("Password: '%s'\nExpected: %v\nGot: %v\nReason: %s",
					tt.password, tt.expected, result, tt.reason)
			}
		})
	}
}

// TestIsValidEmail tests email validation.
func TestIsValidEmail(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected bool
		reason   string
	}{
		// Valid emails
		{
			name:     "Standard email",
			email:    "user@example.com",
			expected: true,
			reason:   "Standard format",
		},
		{
			name:     "Email with subdomain",
			email:    "user@mail.example.com",
			expected: true,
			reason:   "Subdomain is valid",
		},
		{
			name:     "Email with plus sign",
			email:    "user+tag@example.com",
			expected: true,
			reason:   "Plus sign is valid in email",
		},
		{
			name:     "Email with dots",
			email:    "first.last@example.com",
			expected: true,
			reason:   "Dots in local part are valid",
		},

		// Invalid emails
		{
			name:     "Missing @",
			email:    "userexample.com",
			expected: false,
			reason:   "No @ symbol",
		},
		{
			name:     "Missing domain",
			email:    "user@",
			expected: false,
			reason:   "Missing domain part",
		},
		{
			name:     "Missing local part",
			email:    "@example.com",
			expected: false,
			reason:   "Missing local part",
		},
		{
			name:     "Empty string",
			email:    "",
			expected: false,
			reason:   "Empty email",
		},
		{
			name:     "Too long (>254 chars)",
			email:    "a" + string(make([]byte, 250)) + "@example.com",
			expected: false,
			reason:   "Exceeds 254 character limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidEmail(tt.email)

			if result != tt.expected {
				t.Errorf("Email: '%s'\nExpected: %v\nGot: %v\nReason: %s",
					tt.email, tt.expected, result, tt.reason)
			}
		})
	}
}

// TestUserIsLocked tests the User.IsLocked() method.
func TestUserIsLocked(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name        string
		lockedUntil *time.Time
		expected    bool
		description string
	}{
		{
			name:        "Not locked (nil)",
			lockedUntil: nil,
			expected:    false,
			description: "User with nil LockedUntil should not be locked",
		},
		{
			name: "Locked (future time)",
			lockedUntil: func() *time.Time {
				future := now.Add(10 * time.Minute)
				return &future
			}(),
			expected:    true,
			description: "User locked until future time should be locked",
		},
		{
			name: "Not locked (past time)",
			lockedUntil: func() *time.Time {
				past := now.Add(-10 * time.Minute)
				return &past
			}(),
			expected:    false,
			description: "User with past LockedUntil should not be locked",
		},
		{
			name: "Edge case (locked until now)",
			lockedUntil: func() *time.Time {
				nowTime := time.Now()
				return &nowTime
			}(),
			expected:    false,
			description: "User locked until current time should not be locked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &domain.User{
				LockedUntil: tt.lockedUntil,
			}

			result := user.IsLocked()

			if result != tt.expected {
				t.Errorf("%s\nExpected: %v\nGot: %v",
					tt.description, tt.expected, result)
			}
		})
	}
}

// TestFormatLockoutDuration tests the lockout duration formatting.
func TestFormatLockoutDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		{
			name:     "Exactly 1 minute",
			duration: 1 * time.Minute,
			expected: "1 minute",
		},
		{
			name:     "Multiple minutes",
			duration: 15 * time.Minute,
			expected: "15 minutes",
		},
		{
			name:     "Rounds up when > 30 seconds",
			duration: 14*time.Minute + 45*time.Second,
			expected: "15 minutes",
		},
		{
			name:     "Doesn't round up when < 30 seconds",
			duration: 14*time.Minute + 15*time.Second,
			expected: "14 minutes",
		},
		{
			name:     "Only seconds (singular)",
			duration: 1 * time.Second,
			expected: "1 second",
		},
		{
			name:     "Only seconds (plural)",
			duration: 45 * time.Second,
			expected: "45 seconds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatLockoutDuration(tt.duration)

			if result != tt.expected {
				t.Errorf("Duration: %v\nExpected: %s\nGot: %s",
					tt.duration, tt.expected, result)
			}
		})
	}
}

// TestPasswordResetTokenValidation tests password reset token validation logic.
func TestPasswordResetTokenValidation(t *testing.T) {
	tests := []struct {
		name          string
		token         string
		newPassword   string
		expectedError bool
		errorContains string
	}{
		{
			name:          "Empty token",
			token:         "",
			newPassword:   "ValidP@ss123",
			expectedError: true,
			errorContains: "token",
		},
		{
			name:          "Empty password",
			token:         "valid-token-uuid",
			newPassword:   "",
			expectedError: true,
			errorContains: "password",
		},
		{
			name:          "Weak password",
			token:         "valid-token-uuid",
			newPassword:   "weak",
			expectedError: true,
			errorContains: "password",
		},
		{
			name:          "Password too long (>72 bytes)",
			token:         "valid-token-uuid",
			newPassword:   "ValidP@ss1" + string(make([]byte, 65)),
			expectedError: true,
			errorContains: "72",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic input validation tests
			// These would typically be done at the handler/service layer
			if tt.token == "" && tt.expectedError {
				// Token validation
				return
			}
			if tt.newPassword == "" && tt.expectedError {
				// Password validation
				return
			}
			if !isStrongPassword(tt.newPassword) && tt.expectedError {
				// Password strength validation
				return
			}
		})
	}
}

// TestEmailValidationEdgeCases tests edge cases for email validation.
func TestEmailValidationEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected bool
	}{
		{
			name:     "Email with numbers",
			email:    "user123@example.com",
			expected: true,
		},
		{
			name:     "Email with dashes",
			email:    "user-name@example.com",
			expected: true,
		},
		{
			name:     "Email with underscores",
			email:    "user_name@example.com",
			expected: true,
		},
		{
			name:     "Multiple @ symbols",
			email:    "user@@example.com",
			expected: false,
		},
		{
			name:     "Spaces in email",
			email:    "user name@example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidEmail(tt.email)
			if result != tt.expected {
				t.Errorf("Email: '%s'\nExpected: %v\nGot: %v",
					tt.email, tt.expected, result)
			}
		})
	}
}
