package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/Olprog59/go-fun/internal/dto"
	"github.com/Olprog59/go-fun/internal/service"
	"github.com/golang-jwt/jwt/v5"
)

// sha256hex computes the SHA-256 hash of a string and returns it as a hex-encoded string.
// This is used for creating consistent, fixed-size representations of client-specific data
// like IP addresses and User-Agent strings, which can be stored for security auditing
// or to associate refresh tokens with specific clients without storing the raw data.
func sha256hex(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
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

	ipHash := sha256hex(r.RemoteAddr)
	uaHash := sha256hex(r.Header.Get("User-Agent"))
	user, tokenPair, err := h.container.UserSvc.Login(req.Username, req.Password, ipHash, uaHash)
	if err != nil {
		status := http.StatusUnauthorized
		if !errors.Is(err, service.ErrInvalidCredentials) {
			slog.Error("login failed", "err", err, "email", req.Username)
			err = errors.New("authentication failed")
			status = http.StatusInternalServerError
		}
		ErrorResponse(w, err.Error(), status)
		return
	}

	if errors.Is(err, errors.New("email not verified")) {
		ErrorResponse(w, "please verify your email first", http.StatusForbidden)
		return
	}

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

	csrfToken, err := generateCSRFToken()
	if err != nil {
		slog.Error("failed to generate CSRF token", "err", err)
		ErrorResponse(w, "internal server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrfToken,
		Path:     h.container.Config.Auth.CookiePath,
		MaxAge:   int(h.container.Config.Auth.AccessTokenDuration.Seconds()),
		HttpOnly: false,
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
		ErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResponse(w, dto.UserLoginToDTO(user))
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

	_ = h.container.UserSvc.ResendVerification(req.Email)

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

	ipHash := sha256hex(r.RemoteAddr)
	uaHash := sha256hex(r.Header.Get("User-Agent"))

	tokenPair, err := h.container.UserSvc.RefreshToken(req.RefreshToken, ipHash, uaHash)
	if err != nil {
		ErrorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

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

	claims, ok := r.Context().Value(ClaimsContextKey).(*jwt.RegisteredClaims)
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
// 1. Extracts the verification token from the request URL.
// 2. Calls the user repository to find a matching, unexpired token.
// 3. If a valid token is found, it updates the user's record to mark the email as verified
//    and clears the verification token details to prevent reuse.
//
// If the token is missing, invalid, or expired, it returns a "400 Bad Request" error.
// On successful verification, it returns a "200 OK" response with a confirmation message.
func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		ErrorResponse(w, "missing token", http.StatusBadRequest)
		return
	}

	err := h.container.UserRepo.UpdateDBVerify(token)
	if err != nil {
		ErrorResponse(w, "invalid or expired token", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "email verified"})
}
