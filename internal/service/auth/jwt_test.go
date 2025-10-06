package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateJWT_Success(t *testing.T) {
	userID := "user123"
	jwtKey := "this_is_a_very_secret_and_long_enough_key_123456"

	tokenStr, err := GenerateJWT(userID, jwtKey)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if tokenStr == "" {
		t.Fatal("expected a token string, got empty string")
	}

	claims, err := ValidateJWT(tokenStr, jwtKey)
	if err != nil {
		t.Fatalf("expected valid token, got error: %v", err)
	}
	if claims.Subject != userID {
		t.Errorf("expected subject %q, got %q", userID, claims.Subject)
	}
}

func TestGenerateJWT_WeakKey(t *testing.T) {
	userID := "user123"
	jwtKey := "short_key"

	_, err := GenerateJWT(userID, jwtKey)
	if err == nil {
		t.Fatal("expected error for weak key, got nil")
	}
}

func TestValidateJWT_InvalidSignature(t *testing.T) {
	userID := "user123"
	jwtKey := "this_is_a_very_secret_and_long_enough_key_123456"
	wrongKey := "another_very_secret_and_long_enough_key_654321"

	tokenStr, err := GenerateJWT(userID, jwtKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = ValidateJWT(tokenStr, wrongKey)
	if err == nil {
		t.Fatal("expected error for invalid signature, got nil")
	}
}

func TestValidateJWT_InvalidToken(t *testing.T) {
	jwtKey := "this_is_a_very_secret_and_long_enough_key_123456"
	invalidToken := "not.a.valid.token"

	_, err := ValidateJWT(invalidToken, jwtKey)
	if err == nil {
		t.Fatal("expected error for invalid token, got nil")
	}
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	jwtKey := "this_is_a_very_secret_and_long_enough_key_123456"
	claims := &jwt.RegisteredClaims{
		Subject:   "user123",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		Issuer:    "go-fun",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte(jwtKey))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = ValidateJWT(tokenStr, jwtKey)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}
