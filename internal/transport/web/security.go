package web

import (
	"crypto/rand"
	"encoding/base64"
	"io"
)

// generateCSRFToken crée un token anti-CSRF sécurisé.
func generateCSRFToken() (string, error) {
	b := make([]byte, 32) // 32 bytes = 256 bits de données aléatoires
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
