package web

import (
	"encoding/json"
	"net/http"

	"github.com/Olprog59/go-plugins/internal/app"
	"github.com/Olprog59/go-plugins/internal/service"
)

type Handler struct {
	container *app.Container
}

func NewHandler(container *app.Container) *Handler {
	return &Handler{container: container}
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.container.UserSvc.Login(req.Username, req.Password)
	if err != nil {
		if err == service.ErrInvalidCredentials {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		// http.Error(w, "internal error", http.StatusInternalServerError)
		ErrorResponse(w, err)
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"token":    user.Token,
		"username": user.Username,
		"id":       user.ID,
	})
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.container.UserSvc.Register(req.Username, req.Password)
	if err != nil {
		ErrorResponse(w, err)
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"id":       user.ID,
		"username": user.Username,
	})
}

func (h *Handler) Ping(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"message": "pong",
	})
}
