package web

import (
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

func (h *Handler) Home(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(ClaimsContextKey).(*jwt.RegisteredClaims)
	if !ok {
		log.Println("redirect")
		log.Println(claims)
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	log.Println(claims)
	jsonResponse(w, claims)
}
