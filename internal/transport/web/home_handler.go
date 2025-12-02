package web

import (
	"log"
	"net/http"

	"github.com/Olprog59/go-authstarter/internal/service/auth"
)

// Home is the handler for the application's home page or root path.
// It is a protected endpoint that requires authentication.
//
// If the user is authenticated (i.e., valid JWT claims are found in the context),
// it responds with a JSON representation of the user's claims, including their role.
// If the user is not authenticated, it redirects them to the "/login" page.
func (h *Handler) Home(w http.ResponseWriter, r *http.Request) {
	claims, ok := r.Context().Value(ClaimsContextKey).(*auth.CustomClaims)
	if !ok {
		log.Println("redirect")
		log.Println(claims)
		http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
		return
	}

	log.Println(claims)
	jsonResponse(w, claims)
}
