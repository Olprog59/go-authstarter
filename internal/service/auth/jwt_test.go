package auth

import (
	"testing"
	"time"
)

// TestGenerateTokenPair tests JWT token pair generation.
func TestGenerateTokenPair(t *testing.T) {
	secret := "test-secret-key-min-32-chars-long-1234567890"
	userID := int64(123)
	role := "user"
	accessDuration := 15 * time.Minute
	refreshDuration := 30 * 24 * time.Hour

	// Test valid token generation
	tokenPair, err := GenerateTokenPair(userID, role, secret, accessDuration, refreshDuration)
	if err != nil {
		t.Fatalf("Failed to generate token pair: %v", err)
	}

	if tokenPair == nil {
		t.Fatal("Token pair is nil")
	}

	if tokenPair.AccessToken == "" {
		t.Error("Access token is empty")
	}

	if tokenPair.RefreshToken == "" {
		t.Error("Refresh token is empty")
	}

	if tokenPair.ExpiresAt.IsZero() {
		t.Error("ExpiresAt is not set")
	}

	// Verify access token can be validated
	claims, err := ValidateJWT(tokenPair.AccessToken, secret)
	if err != nil {
		t.Fatalf("Failed to validate generated access token: %v", err)
	}

	if claims.Subject != "123" {
		t.Errorf("Expected subject '123', got '%s'", claims.Subject)
	}

	if claims.Role != role {
		t.Errorf("Expected role '%s', got '%s'", role, claims.Role)
	}

	if claims.Issuer != "go-fun" {
		t.Errorf("Expected issuer 'go-fun', got '%s'", claims.Issuer)
	}
}

// TestGenerateTokenPairWeakSecret tests that weak secrets are rejected.
func TestGenerateTokenPairWeakSecret(t *testing.T) {
	weakSecret := "short"
	userID := int64(123)
	role := "user"
	accessDuration := 15 * time.Minute
	refreshDuration := 30 * 24 * time.Hour

	_, err := GenerateTokenPair(userID, role, weakSecret, accessDuration, refreshDuration)
	if err == nil {
		t.Error("Expected error for weak secret, but got none")
	}

	if err.Error() != "JWT key too weak" {
		t.Errorf("Expected 'JWT key too weak' error, got '%s'", err.Error())
	}
}

// TestValidateJWT tests JWT token validation.
func TestValidateJWT(t *testing.T) {
	secret := "test-secret-key-min-32-chars-long-1234567890"
	userID := int64(456)
	role := "admin"
	accessDuration := 15 * time.Minute
	refreshDuration := 30 * 24 * time.Hour

	// Generate a valid token pair
	tokenPair, err := GenerateTokenPair(userID, role, secret, accessDuration, refreshDuration)
	if err != nil {
		t.Fatalf("Failed to generate token pair for validation test: %v", err)
	}

	tests := []struct {
		name          string
		token         string
		secret        string
		expectError   bool
		errorContains string
	}{
		{
			name:        "Valid token",
			token:       tokenPair.AccessToken,
			secret:      secret,
			expectError: false,
		},
		{
			name:          "Invalid secret",
			token:         tokenPair.AccessToken,
			secret:        "wrong-secret-key-min-32-chars-long-12345",
			expectError:   true,
			errorContains: "signature",
		},
		{
			name:        "Empty token",
			token:       "",
			secret:      secret,
			expectError: true,
		},
		{
			name:        "Malformed token",
			token:       "invalid.token.here",
			secret:      secret,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := ValidateJWT(tt.token, tt.secret)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if claims == nil {
					t.Error("Expected claims but got nil")
				}
			}
		})
	}
}

// TestExpiredToken tests that expired tokens are rejected.
func TestExpiredToken(t *testing.T) {
	secret := "test-secret-key-min-32-chars-long-1234567890"
	userID := int64(789)
	role := "user"
	accessDuration := -1 * time.Second // Expired 1 second ago
	refreshDuration := 30 * 24 * time.Hour

	// Generate an already-expired token
	tokenPair, err := GenerateTokenPair(userID, role, secret, accessDuration, refreshDuration)
	if err != nil {
		t.Fatalf("Failed to generate expired token: %v", err)
	}

	// Sleep briefly to ensure the token is definitely expired
	time.Sleep(10 * time.Millisecond)

	// Try to validate the expired token
	_, err = ValidateJWT(tokenPair.AccessToken, secret)
	if err == nil {
		t.Error("Expected error for expired token, but validation succeeded")
	}
}

// TestTokenClaimsContent tests that token claims contain correct data.
func TestTokenClaimsContent(t *testing.T) {
	secret := "test-secret-key-min-32-chars-long-1234567890"
	accessDuration := 15 * time.Minute
	refreshDuration := 30 * 24 * time.Hour

	tests := []struct {
		name   string
		userID int64
		role   string
	}{
		{
			name:   "Regular user",
			userID: 100,
			role:   "user",
		},
		{
			name:   "Admin user",
			userID: 200,
			role:   "admin",
		},
		{
			name:   "Moderator user",
			userID: 300,
			role:   "moderator",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenPair, err := GenerateTokenPair(tt.userID, tt.role, secret, accessDuration, refreshDuration)
			if err != nil {
				t.Fatalf("Failed to generate token: %v", err)
			}

			claims, err := ValidateJWT(tokenPair.AccessToken, secret)
			if err != nil {
				t.Fatalf("Failed to validate token: %v", err)
			}

			// Verify all claims
			if claims.Role != tt.role {
				t.Errorf("Role mismatch: expected '%s', got '%s'", tt.role, claims.Role)
			}

			if claims.Issuer != "go-fun" {
				t.Errorf("Issuer mismatch: expected 'go-fun', got '%s'", claims.Issuer)
			}

			// Verify expiration is set appropriately
			if claims.ExpiresAt == nil {
				t.Error("ExpiresAt claim is nil")
			}

			// Verify IssuedAt is set
			if claims.IssuedAt == nil {
				t.Error("IssuedAt claim is nil")
			}

			// Verify NotBefore is set
			if claims.NotBefore == nil {
				t.Error("NotBefore claim is nil")
			}
		})
	}
}

// TestRefreshTokenUniqueness tests that refresh tokens are unique.
func TestRefreshTokenUniqueness(t *testing.T) {
	secret := "test-secret-key-min-32-chars-long-1234567890"
	userID := int64(999)
	role := "user"
	accessDuration := 15 * time.Minute
	refreshDuration := 30 * 24 * time.Hour

	// Generate multiple token pairs to ensure refresh tokens are unique
	tokens := make(map[string]bool)

	for i := 0; i < 100; i++ {
		tokenPair, err := GenerateTokenPair(userID, role, secret, accessDuration, refreshDuration)
		if err != nil {
			t.Fatalf("Failed to generate token pair: %v", err)
		}

		if tokens[tokenPair.RefreshToken] {
			t.Errorf("Duplicate refresh token generated: %s", tokenPair.RefreshToken)
		}
		tokens[tokenPair.RefreshToken] = true

		// Verify refresh token length (should be 32 bytes in hex = 64 characters)
		if len(tokenPair.RefreshToken) != 64 {
			t.Errorf("Expected refresh token length 64, got %d", len(tokenPair.RefreshToken))
		}
	}
}

// TestCustomClaimsRole tests that custom role claims are properly set.
func TestCustomClaimsRole(t *testing.T) {
	secret := "test-secret-key-min-32-chars-long-1234567890"

	roles := []string{"user", "moderator", "admin"}

	for _, role := range roles {
		t.Run("Role: "+role, func(t *testing.T) {
			tokenPair, err := GenerateTokenPair(1, role, secret, 15*time.Minute, 24*time.Hour)
			if err != nil {
				t.Fatalf("Failed to generate token: %v", err)
			}

			claims, err := ValidateJWT(tokenPair.AccessToken, secret)
			if err != nil {
				t.Fatalf("Failed to validate token: %v", err)
			}

			if claims.Role != role {
				t.Errorf("Expected role '%s', got '%s'", role, claims.Role)
			}
		})
	}
}
