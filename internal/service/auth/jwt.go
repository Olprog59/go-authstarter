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

// CustomClaims extends JWT claims with role / Étend les claims JWT avec le rôle
type CustomClaims struct {
	jwt.RegisteredClaims
	Role string `json:"role"`
}

// TokenPair represents access and refresh tokens / Représente les tokens d'accès et de rafraîchissement
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// RefreshTokenRecord represents refresh token in database / Représente le token de rafraîchissement en BD
type RefreshTokenRecord struct {
	UserID    int64     `db:"user_id"`
	Token     string    `db:"token"`
	ExpiresAt time.Time `db:"expires_at"`
	IsRevoked bool      `db:"is_revoked"`
	issuedAt  time.Time `db:"created_at"`
}

// GenerateTokenPair creates access and refresh tokens / Crée les tokens d'accès et de rafraîchissement
func GenerateTokenPair(userID int64, role, jwtKey string, accessTokenDuration, refreshTokenDuration time.Duration) (*TokenPair, error) {
	if len(jwtKey) < 32 {
		return nil, errors.New("JWT key too weak")
	}

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

// generateSecureToken generates secure random token / Génère un token aléatoire sécurisé
func generateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// ValidateJWT validates JWT token / Valide le token JWT
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

// RefreshTokenStore manages refresh tokens / Gère les tokens de rafraîchissement
type RefreshTokenStore interface {
	SaveRefreshToken(userID int64, token string, expiresAt time.Time) error
	GetRefreshToken(token string) (*RefreshTokenRecord, error)
	RevokeRefreshToken(token string) error
	RevokeAllUserTokens(userID string) error
}

// RefreshTokens refreshes access token / Rafraîchit le token d'accès
func RefreshTokens(refreshToken, role, jwtKey string, store RefreshTokenStore, accessTokenDuration, refreshTokenDuration time.Duration) (*TokenPair, error) {
	tokenRecord, err := store.GetRefreshToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	if tokenRecord.IsRevoked {
		return nil, errors.New("revoked refresh token")
	}

	if time.Now().After(tokenRecord.ExpiresAt) {
		return nil, errors.New("expired refresh token")
	}

	if err := store.RevokeRefreshToken(refreshToken); err != nil {
		return nil, err
	}

	newTokenPair, err := GenerateTokenPair(tokenRecord.UserID, role, jwtKey, accessTokenDuration, refreshTokenDuration)
	if err != nil {
		return nil, err
	}

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
