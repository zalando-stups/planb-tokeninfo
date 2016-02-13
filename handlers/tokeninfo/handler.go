package tokeninfo

import (
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/zalando/planb-tokeninfo/keys"
	"net/http"
)

type tokenInfoHandler struct {
	keyLoader keys.KeyLoader
}

func (h *tokenInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ti, err := h.validateToken(r)
	if err != nil {
		// TODO: consider a debug mode or log
		// as we are no longer returning error details to the user
		writeError(w, "invalid_request", "Access Token not valid")
		return
	}

	resp, err := json.Marshal(ti)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func (h *tokenInfoHandler) validateToken(req *http.Request) (*TokenInfo, error) {
	token, err := jwt.ParseFromRequest(req, jwtValidator(h.keyLoader))
	if err == nil && token.Valid {
		return buildTokenInfo(token)
	} else {
		return nil, err
	}
}

func DefaultTokenInfoHandler() http.Handler {
	return NewTokenInfoHandler(keys.DefaultKeyLoader())
}

func NewTokenInfoHandler(kl keys.KeyLoader) http.Handler {
	return &tokenInfoHandler{keyLoader: kl}
}
