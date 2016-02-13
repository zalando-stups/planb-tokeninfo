package tokeninfo

import (
	"encoding/json"
	"net/http"
)

type TokenInfoError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	statusCode int
}

var (
	ErrInvalidRequest = TokenInfoError{"invalid_request", "Access Token not valid", http.StatusBadRequest}
	ErrInvalidToken = TokenInfoError{"invalid_token", "Access Token not valid", http.StatusUnauthorized}
)

// error response format for the token info endpoint
func Error(w http.ResponseWriter, error TokenInfoError) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(error.statusCode)
	json.NewEncoder(w).Encode(error)
}
