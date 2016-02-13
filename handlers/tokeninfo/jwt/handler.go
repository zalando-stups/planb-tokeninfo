package jwthandler

import (
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"strings"
	"github.com/zalando/planb-tokeninfo/keys"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo"
	"github.com/coreos/dex/pkg/log"
)

type jwtHandler struct {
	keyLoader keys.KeyLoader
}

func (h *jwtHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ti, err := h.validateToken(r)
	if err != nil {
		// TODO: consider a debug mode or log
		// as we are no longer returning error details to the user
		switch err {
		case jwt.ErrNoTokenInRequest:
			tokeninfo.Error(w, tokeninfo.ErrInvalidRequest)
		default:
			log.Debug(err)
			tokeninfo.Error(w, tokeninfo.ErrInvalidToken)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ti)
}

func (h *jwtHandler) Match(r *http.Request) bool {
	token := r.URL.Query().Get("access_token")
	if token == "" {
		return false
	}

	parts := strings.Split(token, ".")

	return len(parts) == 3
}

func (h *jwtHandler) validateToken(req *http.Request) (*TokenInfo, error) {
	token, err := jwt.ParseFromRequest(req, jwtValidator(h.keyLoader))
	if err == nil && token.Valid {
		return newTokenInfo(token)
	} else {
		return nil, err
	}
}

func DefaultJwtHandler() tokeninfo.TokenInfoHandler {
	return NewJwtHandler(keys.DefaultKeyLoader())
}

func NewJwtHandler(kl keys.KeyLoader) tokeninfo.TokenInfoHandler {
	return &jwtHandler{keyLoader: kl}
}
