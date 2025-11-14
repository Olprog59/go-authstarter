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

	"github.com/Olprog59/go-fun/internal/dto"
	"github.com/Olprog59/go-fun/internal/service"
	"github.com/Olprog59/go-fun/internal/service/auth"
)

// sha256hex computes the SHA-256 hash of a string and returns it as a hex-encoded string.
// This is used for creating consistent, fixed-size representations of client-specific data
// like IP addresses and User-Agent strings, which can be stored for security auditing
// or to associate refresh tokens with specific clients without storing the raw data.
func sha256hex(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

// rotateCSRFToken generates a new CSRF token and sets it as a cookie.
// This should be called after sensitive operations (password reset, role change) to invalidate old CSRF tokens.
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
		SameSite: http.SameSiteStrictMode,
		Domain:   h.container.Config.Auth.CookieDomain,
	})

	return nil
}

// setAuthCookies is a helper function that sets both access_token and refresh_token cookies.
// This reduces code duplication between Login and RefreshToken handlers.
// It sets HttpOnly, Secure, and SameSite flags according to the application configuration.
func (h *Handler) setAuthCookies(w http.ResponseWriter, tokenPair *auth.TokenPair) {
	// Set access token cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    tokenPair.AccessToken,
		Path:     h.container.Config.Auth.CookiePath,
		MaxAge:   int(h.container.Config.Auth.AccessTokenDuration.Seconds()),
		HttpOnly: true,
		Secure:   h.container.Config.Auth.CookieSecure,
		SameSite: http.SameSiteStrictMode,
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
		SameSite: http.SameSiteStrictMode,
		Domain:   h.container.Config.Auth.CookieDomain,
	})
}

// Login handles user authentication. It expects a JSON body with 'email' and 'password'.
// On successful authentication, it performs the following actions:
// 1. Generates a new access token and a refresh token.
// 2. Revokes all previous refresh tokens for the user to enhance security.
// 3. Sets the access token and refresh token as secure, HTTP-only cookies.
// 4. Generates and sets a CSRF token as a cookie to protect against Cross-Site Request Forgery.
// 5. Returns a JSON response with the user's ID and email.
//
// The handler protects against enumeration attacks by returning a generic "authentication failed"
// message for both invalid credentials and non-existent users. It also ensures that only
// users with verified emails can log in.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.UserDTOReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Use getIPWithTrustedProxies() to securely extract client IP
	// Only trusts proxy headers if request comes from a configured trusted proxy
	ipHash := sha256hex(getIPWithTrustedProxies(r, h.container.Config.Security.TrustedProxies))
	uaHash := sha256hex(r.Header.Get("User-Agent"))
	user, tokenPair, err := h.container.AuthSvc.Login(req.Username, req.Password, ipHash, uaHash)
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
		// IMPORTANT: CSRF token should have the same lifetime as the refresh token (not access token)
		// This allows the user to continue using the app even after the access token expires
		// and is refreshed. If CSRF token expires after 15 minutes, every refresh operation would fail.
		MaxAge:   int(h.container.Config.Auth.RefreshTokenDuration.Seconds()),
		HttpOnly: false, // Must be false so JavaScript can read it to send in headers
		Secure:   h.container.Config.Auth.CookieSecure,
		SameSite: http.SameSiteStrictMode,
		Domain:   h.container.Config.Auth.CookieDomain,
	})

	jsonResponse(w, dto.UserLoginToDTO(user))
}

// Register handles new user registration. It expects a JSON body with 'email' and 'password'.
// It validates the email format and password strength before attempting to create the user.
// On successful registration, it sends a verification email to the user's address.
//
// To prevent database enumeration, if the email is already registered, the service
// will not return a specific error, though in this implementation, a generic
// "email already registered" is returned. For production, a more opaque message is recommended.
//
// The response contains the newly created user's ID and email, but in a real-world
// scenario, it might be better to return a simple "201 Created" with a message
// prompting the user to check their email for verification.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req *dto.UserDTOReq

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.container.UserSvc.Register(req.Username, req.Password)
	if err != nil {
		// Security: Prevent email enumeration by returning generic message for duplicate emails
		// If email already exists, return success with generic message instead of error
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
	if err := h.container.VerificationSvc.SendVerificationEmail(user); err != nil {
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
// regardless of whether the email exists in the database, is already verified,
// or if an error occurs during the process.
//
// The actual email is sent asynchronously in a separate goroutine, ensuring the
// response time is consistent and does not leak information about the system's state.
func (h *Handler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	_ = h.container.VerificationSvc.ResendVerification(req.Email)

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
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		ErrorResponse(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Use getIPWithTrustedProxies() to securely extract client IP
	// This ensures consistency with the stored IP hash during login
	ipHash := sha256hex(getIPWithTrustedProxies(r, h.container.Config.Security.TrustedProxies))
	uaHash := sha256hex(r.Header.Get("User-Agent"))

	tokenPair, err := h.container.AuthSvc.RefreshToken(req.RefreshToken, ipHash, uaHash)
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
//
// This handler performs the following steps:
// 1. Retrieves the JWT claims from the context.
// 2. Parses the user ID from the 'Subject' field of the claims.
// 3. Fetches the full user details from the database using the user ID.
// 4. Returns a JSON response containing the user's public information (ID and email).
//
// If the token is invalid, expired, or the user is not found, it returns an
// appropriate HTTP error (401 Unauthorized).
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

	user, err := h.container.UserSvc.GetUser(userID)
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

	err := h.container.VerificationSvc.VerifyEmail(token)
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
	var req dto.PasswordResetRequestDTO

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Call service - always returns success for security (prevents email enumeration)
	err := h.container.PasswordSvc.RequestPasswordReset(req.Email)
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
	var req dto.PasswordResetDTO

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
	err := h.container.PasswordSvc.ResetPassword(req.Token, req.NewPassword)
	if err != nil {
		ErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Rotate CSRF token after password reset for security
	// (password reset is a sensitive operation that changes authentication state)
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
