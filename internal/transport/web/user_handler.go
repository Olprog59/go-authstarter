package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Olprog59/go-fun/internal/dto"
	"github.com/Olprog59/go-fun/internal/service"
	"github.com/Olprog59/go-fun/internal/service/auth"
)

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req dto.UserDTOReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, tokenPair, err := h.container.UserSvc.Login(req.Username, req.Password)
	if err != nil {
		status := http.StatusUnauthorized
		if !errors.Is(err, service.ErrInvalidCredentials) {
			status = http.StatusInternalServerError
		}
		ErrorResponse(w, err.Error(), status)
		return
	}

	// Cookies HTTP-only
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    tokenPair.AccessToken,
		Path:     "/",
		MaxAge:   int(15 * time.Minute / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    tokenPair.RefreshToken,
		Path:     "/",
		MaxAge:   int(7 * 24 * time.Hour / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
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

	// Appel au service pour renouveler les tokens
	tokenPair, err := h.container.UserSvc.RefreshToken(req.RefreshToken)
	if err != nil {
		ErrorResponse(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Mettre à jour les cookies HttpOnly
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    tokenPair.AccessToken,
		Path:     "/",
		MaxAge:   int(15 * time.Minute / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    tokenPair.RefreshToken,
		Path:     "/",
		MaxAge:   int(7 * 24 * time.Hour / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	// Répondre avec les tokens en JSON au cas où front voudrait aussi les capturer
	jsonResponse(w, tokenPair)
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	// Récupérer le token depuis le cookie ou header Authorization
	var tokenStr string

	cookie, err := r.Cookie("access_token")
	if err == nil {
		tokenStr = cookie.Value
	} else {
		// Essayer Authorization header Bearer
		authHeader := r.Header.Get("Authorization")
		if len(authHeader) > 7 && strings.ToLower(authHeader[:7]) == "bearer " {
			tokenStr = authHeader[7:]
		}
	}

	if tokenStr == "" {
		ErrorResponse(w, "Token manquant", http.StatusUnauthorized)
		return
	}

	claims, err := auth.ValidateJWT(tokenStr, h.container.Config.JWTKey)
	if err != nil {
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
