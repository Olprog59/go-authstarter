package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// CustomClaims extends jwt.RegisteredClaims to include custom application-specific claims.
// This allows us to include additional information in the JWT, such as the user's role.
type CustomClaims struct {
	jwt.RegisteredClaims        // Embeds standard JWT claims (subject, issuer, expiration, etc.)
	Role                 string `json:"role"` // The user's role for authorization purposes.
}

// TokenPair represents a pair of access and refresh tokens issued to a user.
// Access tokens are short-lived and used for authenticating API requests,
// while refresh tokens are long-lived and used to obtain new access tokens.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`  // The JWT access token.
	RefreshToken string    `json:"refresh_token"` // The opaque refresh token.
	ExpiresAt    time.Time `json:"expires_at"`    // The expiration time of the access token.
}

// RefreshTokenRecord represents the structure of a refresh token as stored in the database.
// It includes metadata necessary for managing and validating refresh tokens.
type RefreshTokenRecord struct {
	UserID    int64     `db:"user_id"`    // The ID of the user to whom this token belongs.
	Token     string    `db:"token"`      // The hashed refresh token value.
	ExpiresAt time.Time `db:"expires_at"` // The expiration time of the refresh token.
	IsRevoked bool      `db:"is_revoked"` // A flag indicating if the token has been revoked.
	issuedAt  time.Time `db:"created_at"` // The creation time of the token.
}

// GenerateTokenPair creates a new pair of JWT access token and a cryptographically secure refresh token.
//
// Parameters:
//   - userID: The ID of the user for whom the tokens are being generated.
//   - role: The user's role to include in the JWT claims for authorization.
//   - jwtKey: The secret key used to sign the JWT access token. Must be at least 32 characters long.
//   - accessTokenDuration: The duration for which the access token will be valid.
//   - refreshTokenDuration: The duration for which the refresh token will be valid.
//
// Returns:
//   - A pointer to a `TokenPair` containing the new access token, refresh token, and access token expiration.
//   - An error if the JWT key is too weak, or if there's an issue generating the tokens.
func GenerateTokenPair(userID int64, role, jwtKey string, accessTokenDuration, refreshTokenDuration time.Duration) (*TokenPair, error) {
	if len(jwtKey) < 32 {
		return nil, errors.New("JWT key too weak")
	}

	// Generate the access token (short duration)
	expiresAt := time.Now().Add(accessTokenDuration)
	accessClaims := &CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatInt(userID, 10),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "go-fun",
		},
		Role: role,
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString([]byte(jwtKey))
	if err != nil {
		return nil, err
	}

	// Generate the refresh token (long duration, random value)
	refreshToken, err := generateSecureToken()
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}

// generateSecureToken generates a cryptographically secure random token string.
// It uses `crypto/rand` to generate a 32-byte random sequence, which is then
// hex-encoded to produce a 64-character string. This is suitable for use as
// refresh tokens or other sensitive, opaque identifiers.
func generateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// ValidateJWT parses and validates a JWT access token.
// It verifies the token's signature using the provided `jwtKey` and checks
// standard claims like issuer and expiration, and extracts custom claims including the user's role.
//
// Parameters:
//   - tokenStr: The raw JWT string to validate.
//   - jwtKey: The secret key used to verify the token's signature.
//
// Returns:
//   - A pointer to `CustomClaims` if the token is valid and successfully parsed.
//   - An error if the token is invalid (e.g., bad signature, expired, wrong issuer, unexpected signing method).
func ValidateJWT(tokenStr, jwtKey string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing algorithm: %v", token.Header["alg"])
		}
		return []byte(jwtKey), nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		if claims.Issuer != "go-fun" {
			return nil, errors.New("invalid issuer")
		}
		return claims, nil
	}

	return nil, jwt.ErrTokenInvalidClaims
}

// RefreshTokenStore defines the interface for managing refresh tokens in a persistence layer.
// This interface is used by the `RefreshTokens` function to interact with the underlying
// storage mechanism for refresh token records.
type RefreshTokenStore interface {
	// SaveRefreshToken stores a new refresh token record.
	SaveRefreshToken(userID int64, token string, expiresAt time.Time) error
	// GetRefreshToken retrieves a refresh token record by its token string.
	GetRefreshToken(token string) (*RefreshTokenRecord, error)
	// RevokeRefreshToken marks a specific refresh token as revoked.
	RevokeRefreshToken(token string) error
	// RevokeAllUserTokens revokes all refresh tokens for a given user ID.
	RevokeAllUserTokens(userID string) error
}

// RefreshTokens handles the logic for refreshing an access token using a refresh token.
// This function implements token rotation, a security best practice.
//
// The process involves:
// 1.  Validating the provided refresh token against the `RefreshTokenStore`.
// 2.  Performing security checks: ensuring the token is not revoked and not expired.
// 3.  Revoking the old refresh token immediately to prevent replay attacks.
// 4.  Generating a new `TokenPair` (new access token and new refresh token).
// 5.  Saving the new refresh token to the `RefreshTokenStore`.
//
// Parameters:
//   - refreshToken: The old refresh token string provided by the client.
//   - role: The user's role to include in the new JWT claims.
//   - jwtKey: The secret key for signing new access tokens.
//   - store: An implementation of the `RefreshTokenStore` interface.
//   - accessTokenDuration: The desired duration for the new access token.
//   - refreshTokenDuration: The desired duration for the new refresh token.
//
// Returns:
//   - A pointer to the new `TokenPair` on successful refresh.
//   - An error if the refresh token is invalid, expired, revoked, or if token generation/storage fails.
func RefreshTokens(refreshToken, role, jwtKey string, store RefreshTokenStore, accessTokenDuration, refreshTokenDuration time.Duration) (*TokenPair, error) {
	// Check the refresh token in the database
	tokenRecord, err := store.GetRefreshToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Security checks
	if tokenRecord.IsRevoked {
		return nil, errors.New("revoked refresh token")
	}

	if time.Now().After(tokenRecord.ExpiresAt) {
		return nil, errors.New("expired refresh token")
	}

	// Token rotation: revoke the old one
	if err := store.RevokeRefreshToken(refreshToken); err != nil {
		return nil, err
	}

	// Generate a new pair of tokens
	newTokenPair, err := GenerateTokenPair(tokenRecord.UserID, role, jwtKey, accessTokenDuration, refreshTokenDuration)
	if err != nil {
		return nil, err
	}

	// Save the new refresh token
	err = store.SaveRefreshToken(
		tokenRecord.UserID,
		newTokenPair.RefreshToken,
		time.Now().Add(refreshTokenDuration),
	)
	if err != nil {
		return nil, err
	}

	return newTokenPair, nil
}
