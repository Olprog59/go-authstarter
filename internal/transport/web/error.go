package web

import (
	"encoding/json"
	"net/http"
)

func ErrorResponse(w http.ResponseWriter, err error) {
	json.NewEncoder(w).Encode(map[string]any{
		"error": err.Error(),
	})
}
