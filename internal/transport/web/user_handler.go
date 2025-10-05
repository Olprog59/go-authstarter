package web

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Olprog59/go-fun/internal/dto"
)

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req *dto.UserDTOReq

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user, err := h.container.UserSvc.Login(req.Username, req.Password)
	if err != nil {
		ErrorResponse(w, err.Error(), http.StatusInternalServerError)
		return
	}

	expireTime := int(time.Now().Add(time.Hour * 24).Unix())

	cookie := &http.Cookie{
		Name:     "auth",
		Value:    user.Token,
		Path:     "/",
		MaxAge:   expireTime,
		Secure:   false,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	http.SetCookie(w, cookie)

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
