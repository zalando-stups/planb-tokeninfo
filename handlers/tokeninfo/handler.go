package tokeninfo

import (
	"encoding/json"
	"net/http"
)

type tokenInfoHandler struct {
}

func (h *tokenInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ti, err := validateToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	resp, err := json.Marshal(ti)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func NewTokenInfoHandler() http.Handler {
	return &tokenInfoHandler{}
}
