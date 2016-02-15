package jwthandler

import (
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo"
	"github.com/zalando/planb-tokeninfo/keys"
	"log"
	"net/http"
	"strings"
	"time"
)

type jwtHandler struct {
	keyLoader keys.KeyLoader
}

func (h *jwtHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ti, err := h.validateToken(r)
	if err != nil {
		switch err {
		case jwt.ErrNoTokenInRequest:
			tokeninfo.Error(w, tokeninfo.ErrInvalidRequest)
		default:
			log.Println(err)
			tokeninfo.Error(w, tokeninfo.ErrInvalidToken)
		}
		log.Println(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ti)
}

func (h *jwtHandler) Match(r *http.Request) bool {
	token := tokeninfo.AccessTokenFromRequest(r)
	if token == "" {
		return false
	}

	parts := strings.Split(token, ".")

	return len(parts) == 3
}

func (h *jwtHandler) validateToken(req *http.Request) (*TokenInfo, error) {
	token, err := jwt.ParseFromRequest(req, jwtValidator(h.keyLoader))
	if err == nil && token.Valid {
		return newTokenInfo(token, time.Now())
	} else {
		log.Println("Failed to validate token: ", err)
		return nil, err
	}
}

func NewJwtHandler(kl keys.KeyLoader) tokeninfo.TokenInfoHandler {
	return &jwtHandler{keyLoader: kl}
}
