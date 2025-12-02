package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/Olprog59/go-authstarter/internal/dto"
	"github.com/Olprog59/go-authstarter/internal/service"
	"github.com/Olprog59/go-authstarter/internal/service/auth"
)

// sha256hex computes SHA-256 hash of string / Calcule le hash SHA-256 d'une chaîne
func sha256hex(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

// rotateCSRFToken generates new CSRF token / Génère un nouveau token CSRF
func (h *Handler) rotateCSRFToken(w http.ResponseWriter) error {
	csrfToken, err := generateCSRFToken()
	if err != nil {
		slog.Error("failed to generate CSRF token for rotation", "err", err)
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Path:     h.container.Config.Auth.CookiePath,
		MaxAge:   int(h.container.Config.Auth.RefreshTokenDuration.Seconds()),
		HttpOnly: false, // Must be false so JavaScript can read it
		Secure:   h.container.Config.Auth.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Domain:   h.container.Config.Auth.CookieDomain,
	})

	return nil
}

// setAuthCookies sets access and refresh token cookies / Définit les cookies d'accès et de rafraîchissement
func (h *Handler) setAuthCookies(w http.ResponseWriter, tokenPair *auth.TokenPair) {
	// Set access token cookie
	// Note: Domain is left empty for localhost to work properly across ports
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    tokenPair.AccessToken,
		Path:     h.container.Config.Auth.CookiePath,
		MaxAge:   int(h.container.Config.Auth.AccessTokenDuration.Seconds()),
		HttpOnly: true,
		Secure:   h.container.Config.Auth.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Domain:   h.container.Config.Auth.CookieDomain,
	})

	// Set refresh token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    tokenPair.RefreshToken,
		Path:     h.container.Config.Auth.CookiePath,
		MaxAge:   int(h.container.Config.Auth.RefreshTokenDuration.Seconds()),
		HttpOnly: true,
		Secure:   h.container.Config.Auth.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Domain:   h.container.Config.Auth.CookieDomain,
	})
}

// Login handles user authentication / Gère l'authentification de l'utilisateur
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	// Limit request body size to 1MB to prevent DoS attacks
	limitRequestBody(w, r, 1*1024*1024)

	var req dto.UserDTOReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Check if error is due to body too large
		if err.Error() == "http: request body too large" {
			ErrorResponse(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		ErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Use getIPWithTrustedProxies() to securely extract client IP
	// Only trusts proxy headers if request comes from a configured trusted proxy
	ipHash := sha256hex(getIPWithTrustedProxies(r, h.container.Config.Security.TrustedProxies))
	uaHash := sha256hex(r.Header.Get("User-Agent"))
	user, tokenPair, err := h.container.AuthSvc.Login(r.Context(), req.Username, req.Password, ipHash, uaHash)
	if err != nil {
		status := http.StatusUnauthorized

		// Determine login failure reason for metrics
		errMsg := err.Error()
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			h.container.Metrics.RecordLoginAttempt("failure")
		case strings.Contains(errMsg, "locked"):
			h.container.Metrics.RecordLoginAttempt("locked")
		case strings.Contains(errMsg, "not verified"):
			h.container.Metrics.RecordLoginAttempt("unverified")
		default:
			slog.Error("login failed", "err", err, "email", req.Username)
			err = errors.New("authentication failed")
			status = http.StatusInternalServerError
		}

		ErrorResponse(w, err.Error(), status)
		return
	}

	// Successful login
	h.container.Metrics.RecordLoginAttempt("success")

	// Set authentication cookies (access_token and refresh_token)
	h.setAuthCookies(w, tokenPair)

	csrfToken, err := generateCSRFToken()
	if err != nil {
		slog.Error("failed to generate CSRF token", "err", err)
		ErrorResponse(w, "internal server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:  "csrf_token",
		Value: csrfToken,
		Path:  h.container.Config.Auth.CookiePath,
		// CSRF token lifetime matches refresh token / Durée de vie du CSRF = refresh token
		MaxAge:   int(h.container.Config.Auth.RefreshTokenDuration.Seconds()),
		HttpOnly: false, // Must be false so JavaScript can read it to send in headers
		Secure:   h.container.Config.Auth.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Domain:   h.container.Config.Auth.CookieDomain,
	})

	jsonResponse(w, dto.UserLoginToDTO(user))
}

// Register handles new user registration / Gère l'inscription des utilisateurs
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	// Limit request body size to 1MB to prevent DoS attacks
	limitRequestBody(w, r, 1*1024*1024)

	var req *dto.UserDTOReq

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err.Error() == "http: request body too large" {
			ErrorResponse(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.container.UserSvc.Register(r.Context(), req.Username, req.Password)
	if err != nil {
		// Prevent email enumeration / Évite l'énumération des emails
		if err.Error() == "email already registered" {
			w.WriteHeader(http.StatusOK)
			jsonResponse(w, map[string]string{
				"message": "Registration successful. Please check your email to verify your account.",
			})
			return
		}
		ErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Record successful registration
	h.container.Metrics.RecordRegistration()

	// Send verification email asynchronously
	if err := h.container.VerificationSvc.SendVerificationEmail(r.Context(), user); err != nil {
		slog.Error("failed to send verification email", "email", user.Email, "err", err)
		// Don't fail the registration - email sending is best-effort
	}

	// Return generic success message (same as duplicate email case)
	w.WriteHeader(http.StatusOK)
	jsonResponse(w, map[string]string{
		"message": "Registration successful. Please check your email to verify your account.",
		"user":    dto.UserLoginToDTO(user).Email,
	})
}

// ResendVerification handles requests to resend a verification email.
// It expects a JSON body containing the user's 'email'.
//
// This endpoint is designed to be "timing-safe" to prevent email enumeration attacks.
// It will always return a successful (200 OK) response with a generic message,
// Timing-safe to prevent email enumeration / Sécurisé contre l'énumération des emails
func (h *Handler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	// Limit request body size to 1MB to prevent DoS attacks
	limitRequestBody(w, r, 1*1024*1024)

	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err.Error() == "http: request body too large" {
			ErrorResponse(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	_ = h.container.VerificationSvc.ResendVerification(r.Context(), req.Email)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "If the email exists and is not verified, a verification link has been sent",
	})
}

// RefreshToken handles the renewal of access tokens using a refresh token.
// It expects a JSON body with a 'refresh_token'.
//
// This endpoint implements token rotation:
// 1. It validates the provided refresh token against the database.
// 2. It checks that the token is not expired or revoked.
// 3. To prevent replay attacks, the old refresh token is immediately revoked.
// 4. A new pair of access and refresh tokens is generated.
// 5. The new tokens are set as secure, HTTP-only cookies.
//
// The client's IP address and User-Agent are hashed and associated with the new
// refresh token to bind it to a specific client, adding an extra layer of security.
func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	// Limit request body size to 1MB to prevent DoS attacks
	limitRequestBody(w, r, 1*1024*1024)

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err.Error() == "http: request body too large" {
			ErrorResponse(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		ErrorResponse(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.RefreshToken == "" {
		ErrorResponse(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Use getIPWithTrustedProxies() to securely extract client IP
	// This ensures consistency with the stored IP hash during login
	ipHash := sha256hex(getIPWithTrustedProxies(r, h.container.Config.Security.TrustedProxies))
	uaHash := sha256hex(r.Header.Get("User-Agent"))

	tokenPair, err := h.container.AuthSvc.RefreshToken(r.Context(), req.RefreshToken, ipHash, uaHash)
	if err != nil {
		// Determine refresh failure reason for metrics
		errMsg := err.Error()
		switch {
		case strings.Contains(errMsg, "binding"):
			h.container.Metrics.RecordTokenRefresh("binding_failure")
			h.container.Metrics.RecordTokenBindingFailure()
		case strings.Contains(errMsg, "expired") || strings.Contains(errMsg, "revoked"):
			h.container.Metrics.RecordTokenRefresh("expired")
		default:
			h.container.Metrics.RecordTokenRefresh("invalid")
		}

		ErrorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Successful token refresh
	h.container.Metrics.RecordTokenRefresh("success")

	// Set authentication cookies (access_token and refresh_token)
	h.setAuthCookies(w, tokenPair)

	jsonResponse(w, tokenPair)
}

// Me is a protected endpoint that returns the details of the currently authenticated user.
// It relies on the Auth middleware, which validates the JWT access token and extracts
// the user's claims, placing them in the request context.
// Me returns current user details / Retourne les détails de l'utilisateur courant
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(ClaimsContextKey).(*auth.CustomClaims)
	if !ok {
		ErrorResponse(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		ErrorResponse(w, "Invalid user", http.StatusUnauthorized)
		return
	}

	user, err := h.container.UserSvc.GetUser(r.Context(), userID)
	if err != nil {
		ErrorResponse(w, "User not found", http.StatusUnauthorized)
		return
	}

	jsonResponse(w, dto.UserLoginToDTO(user))
}

// VerifyEmail handles the email verification process. It is typically triggered
// when a user clicks the verification link sent to their email.
//
// The handler expects a 'token' as a URL query parameter. It performs the following actions:
//  1. Extracts the verification token from the request URL.
//  2. Calls the user repository to find a matching, unexpired token.
//  3. If a valid token is found, it updates the user's record to mark the email as verified
//     and clears the verification token details to prevent reuse.
//
// If the token is missing, invalid, or expired, it returns a "400 Bad Request" error.
// On successful verification, it returns a "200 OK" response with a confirmation message.
func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		ErrorResponse(w, "missing token", http.StatusBadRequest)
		return
	}

	err := h.container.VerificationSvc.VerifyEmail(r.Context(), token)
	if err != nil {
		h.container.Metrics.RecordEmailVerification("failure")
		ErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Successful email verification
	h.container.Metrics.RecordEmailVerification("success")

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "email verified"})
}

// RequestPasswordReset handles the request to initiate a password reset.
// It expects a JSON body with the user's 'email'.
//
// This endpoint is designed to be "timing-safe" to prevent email enumeration attacks.
// It will always return a successful (200 OK) response with a generic message,
// regardless of whether the email exists in the database or if an error occurs.
//
// If the email exists, a password reset email is sent with a time-limited token (1 hour).
// The token can only be used once to reset the password.
//
// Rate limiting is applied to prevent abuse of the email sending functionality.
func (h *Handler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	// Limit request body size to 1MB to prevent DoS attacks
	limitRequestBody(w, r, 1*1024*1024)

	var req dto.PasswordResetRequestDTO

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err.Error() == "http: request body too large" {
			ErrorResponse(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		ErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Prevent email enumeration / Évite l'énumération des emails
	err := h.container.PasswordSvc.RequestPasswordReset(r.Context(), req.Email)
	if err != nil {
		// This shouldn't happen as RequestPasswordReset always returns nil
		// But handle it gracefully just in case
		slog.Error("Unexpected error in RequestPasswordReset", "error", err)
	}

	// Always return success to prevent email enumeration
	w.WriteHeader(http.StatusOK)
	jsonResponse(w, map[string]string{
		"message": "If an account with that email exists, a password reset link has been sent.",
	})
}

// Logout handles user logout by revoking all refresh tokens and clearing cookies.
// This is a protected endpoint that requires authentication.
//
// Security features:
// 1. Revokes all refresh tokens for the user (logout from all devices)
// 2. Clears access_token, refresh_token, and csrf_token cookies
// 3. Returns success message
//
// Returns:
//   - 200 OK with success message
//   - 401 Unauthorized if not authenticated
//   - 500 Internal Server Error if token revocation fails
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	// Get user ID from context (set by Auth middleware)
	claims, ok := r.Context().Value(ClaimsContextKey).(*auth.CustomClaims)
	if !ok {
		ErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		slog.Error("invalid user ID in claims", "subject", claims.Subject, "err", err)
		ErrorResponse(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Revoke all refresh tokens for this user
	if err := h.container.AuthSvc.RevokeAllTokens(r.Context(), userID); err != nil {
		slog.Error("failed to revoke tokens during logout", "user_id", userID, "err", err)
		ErrorResponse(w, "Logout failed", http.StatusInternalServerError)
		return
	}

	// Clear all auth-related cookies
	clearCookie := func(name string) {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     h.container.Config.Auth.CookiePath,
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   h.container.Config.Auth.CookieSecure,
			SameSite: http.SameSiteLaxMode,
			Domain:   h.container.Config.Auth.CookieDomain,
		})
	}

	clearCookie("access_token")
	clearCookie("refresh_token")

	// CSRF token also needs HttpOnly: false
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Path:     h.container.Config.Auth.CookiePath,
		MaxAge:   -1,
		HttpOnly: false,
		Secure:   h.container.Config.Auth.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Domain:   h.container.Config.Auth.CookieDomain,
	})

	// Success response
	w.WriteHeader(http.StatusOK)
	jsonResponse(w, map[string]string{
		"message": "Logged out successfully",
	})
}

// ResetPassword handles the completion of a password reset.
// It expects a JSON body with 'token' (from the email link) and 'new_password'.
//
// Security features:
// 1. Validates the reset token (checks existence and expiration)
// 2. Enforces password strength policy
// 3. Invalidates the token after use (one-time use)
// 4. Revokes all refresh tokens to force re-login
//
// Returns:
//   - 200 OK with success message if password was reset
//   - 400 Bad Request if token is invalid/expired or password is weak
func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	// Limit request body size to 1MB to prevent DoS attacks
	limitRequestBody(w, r, 1*1024*1024)

	var req dto.PasswordResetDTO

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err.Error() == "http: request body too large" {
			ErrorResponse(w, "Request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		ErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate inputs
	if req.Token == "" {
		ErrorResponse(w, "Token is required", http.StatusBadRequest)
		return
	}

	if req.NewPassword == "" {
		ErrorResponse(w, "New password is required", http.StatusBadRequest)
		return
	}

	// Reset password
	err := h.container.PasswordSvc.ResetPassword(r.Context(), req.Token, req.NewPassword)
	if err != nil {
		ErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Rotate CSRF token after password reset / Rotation du CSRF après réinitialisation
	if err := h.rotateCSRFToken(w); err != nil {
		// Log error but don't fail the request - password was already reset successfully
		slog.Error("failed to rotate CSRF token after password reset", "err", err)
	}

	// Success
	w.WriteHeader(http.StatusOK)
	jsonResponse(w, map[string]string{
		"message": "Password has been reset successfully. You can now login with your new password.",
	})
}
