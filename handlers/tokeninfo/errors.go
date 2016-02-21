package tokeninfo

import (
	"encoding/json"
	"log"
	"net/http"
)

// Error type is used to wrap standard error messages that can be easily marshaled to JSON
type Error struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	statusCode       int
}

var (
	// ErrInvalidRequest should be used whenever the receiver failed to parse the request
	ErrInvalidRequest = Error{"invalid_request", "Access Token not valid", http.StatusBadRequest}
	// ErrInvalidToken should be used whenever the receiver failed to validate a JWT Token
	ErrInvalidToken = Error{"invalid_token", "Access Token not valid", http.StatusUnauthorized}
)

// WriteError will write the Error e to the response writer, marshaled as JSON, and with the respective Status Code
func WriteError(w http.ResponseWriter, e Error) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(e.statusCode)
	if err := json.NewEncoder(w).Encode(e); err != nil {
		log.Println("Failed to finish error response: ", err)
	}
}
