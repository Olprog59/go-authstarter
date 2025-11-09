package web

import (
	"crypto/rand"
	"encoding/base64"
	"io"
)

// generateCSRFToken creates a secure, random token for CSRF (Cross-Site Request Forgery) protection.
// It generates 32 random bytes using `crypto/rand` and then encodes them into a URL-safe
// base64 string. This token is used in the "Double Submit Cookie" pattern, where it is
// sent to the client in a cookie and must be returned in a matching HTTP header for
// state-changing requests.
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
