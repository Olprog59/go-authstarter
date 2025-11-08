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

type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type RefreshTokenRecord struct {
	UserID    int64     `db:"user_id"`
	Token     string    `db:"token"`
	ExpiresAt time.Time `db:"expires_at"`
	IsRevoked bool      `db:"is_revoked"`
	issuedAt  time.Time `db:"created_at"`
}

func GenerateTokenPair(userID int64, jwtKey string, accessTokenDuration, refreshTokenDuration time.Duration) (*TokenPair, error) {
	if len(jwtKey) < 32 {
		return nil, errors.New("JWT key trop faible")
	}

	// Générer l'access token (courte durée)
	expiresAt := time.Now().Add(accessTokenDuration)
	accessClaims := &jwt.RegisteredClaims{
		Subject:   strconv.FormatInt(userID, 10),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "go-fun",
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString([]byte(jwtKey))
	if err != nil {
		return nil, err
	}

	// Générer le refresh token (longue durée, valeur aléatoire)
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

// Génère un token cryptographiquement sécurisé
func generateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func ValidateJWT(tokenStr, jwtKey string) (*jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("algorithme de signature inattendu: %v", token.Header["alg"])
		}
		return []byte(jwtKey), nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		if claims.Issuer != "go-fun" {
			return nil, errors.New("invalid issuer")
		}
		return claims, nil
	}

	return nil, jwt.ErrTokenInvalidClaims
}

// Interface pour la gestion des refresh tokens en base
type RefreshTokenStore interface {
	SaveRefreshToken(userID int64, token string, expiresAt time.Time) error
	GetRefreshToken(token string) (*RefreshTokenRecord, error)
	RevokeRefreshToken(token string) error
	RevokeAllUserTokens(userID string) error
}

// Fonction pour renouveler les tokens
func RefreshTokens(refreshToken, jwtKey string, store RefreshTokenStore, accessTokenDuration, refreshTokenDuration time.Duration) (*TokenPair, error) {
	// Vérifier le refresh token en base
	tokenRecord, err := store.GetRefreshToken(refreshToken)
	if err != nil {
		return nil, errors.New("refresh token invalide")
	}

	// Vérifications de sécurité
	if tokenRecord.IsRevoked {
		return nil, errors.New("refresh token révoqué")
	}

	if time.Now().After(tokenRecord.ExpiresAt) {
		return nil, errors.New("refresh token expiré")
	}

	// Rotation du token : révoquer l'ancien
	if err := store.RevokeRefreshToken(refreshToken); err != nil {
		return nil, err
	}

	// Générer une nouvelle paire de tokens
	newTokenPair, err := GenerateTokenPair(tokenRecord.UserID, jwtKey, accessTokenDuration, refreshTokenDuration)
	if err != nil {
		return nil, err
	}

	// Sauvegarder le nouveau refresh token
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
