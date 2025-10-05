package web

import "net/http"

func NewMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()

	mux.Handle("POST /login", chain(h.Login, Logging))
	mux.Handle("POST /register", chain(h.Register, Logging))
	mux.Handle("GET /{$}", chain(h.Home, Logging, Auth))

	return mux
}
