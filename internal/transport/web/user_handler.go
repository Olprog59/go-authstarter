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

func sha256hex(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

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

	// Cookies HTTP-only
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

	jsonResponse(w, dto.UserLoginToDTO(user))
}

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

func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		ErrorResponse(w, "Requête invalide", http.StatusBadRequest)
		return
	}

	ipHash := sha256hex(r.RemoteAddr)
	uaHash := sha256hex(r.Header.Get("User-Agent"))

	// Appel au service pour renouveler les tokens
	tokenPair, err := h.container.UserSvc.RefreshToken(req.RefreshToken, ipHash, uaHash)
	if err != nil {
		ErrorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Mettre à jour les cookies HttpOnly
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

	// Répondre avec les tokens en JSON au cas où front voudrait aussi les capturer
	jsonResponse(w, tokenPair)
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	// Le middleware Auth a déjà validé le token et placé les claims dans le contexte.
	claims, ok := r.Context().Value(ClaimsContextKey).(*jwt.RegisteredClaims)
	if !ok {
		ErrorResponse(w, "Token invalide ou expiré", http.StatusUnauthorized)
		return
	}

	userID, err := strconv.ParseInt(claims.Subject, 10, 64)
	if err != nil {
		ErrorResponse(w, "Utilisateur invalide", http.StatusUnauthorized)
		return
	}

	user, err := h.container.UserSvc.GetUser(userID)
	if err != nil {
		ErrorResponse(w, "Utilisateur non trouvé", http.StatusUnauthorized)
		return
	}

	jsonResponse(w, dto.UserLoginToDTO(user))
}

func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		ErrorResponse(w, "missing token", http.StatusBadRequest)
		return
	}

	// Mettre à jour dans la DB
	err := h.container.UserRepo.UpdateDBVerify(token)
	if err != nil {
		ErrorResponse(w, "invalid or expired token", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "email verified"})
}
