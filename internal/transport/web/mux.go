package web

import "net/http"

func NewMux(h *Handler) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("POST /api/login", chain(h.Login, Logging))
	mux.Handle("POST /api/register", chain(h.Register, Logging))

	mux.Handle("POST /api/refresh", chain(h.RefreshToken, Logging, Auth))
	mux.Handle("POST /api/me", chain(h.Me, Logging, Auth))

	mux.Handle("GET /{$}", chain(h.Home, Logging, Auth))

	return corsMiddleware(mux)
}
