package tokeninfo

import (
	"encoding/json"
	"github.com/coreos/dex/pkg/log"
	"net/http"
)

type TokenInfoError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	statusCode       int
}

var (
	ErrInvalidRequest = TokenInfoError{"invalid_request", "Access Token not valid", http.StatusBadRequest}
	ErrInvalidToken   = TokenInfoError{"invalid_token", "Access Token not valid", http.StatusUnauthorized}
)

// error response format for the token info endpoint
func Error(w http.ResponseWriter, terr TokenInfoError) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(terr.statusCode)
	err := json.NewEncoder(w).Encode(terr)
	if err != nil {
		log.Infof("Failed to finish error response: %q", err)
	}
}
