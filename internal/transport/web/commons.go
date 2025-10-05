package web

import (
	"encoding/json"
	"net/http"

	"github.com/Olprog59/go-fun/internal/app"
)

type Handler struct {
	container *app.Container
}

func NewHandler(container *app.Container) *Handler {
	return &Handler{container: container}
}

func ErrorResponse(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{
		"error": message,
	})
}

func jsonResponse(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
