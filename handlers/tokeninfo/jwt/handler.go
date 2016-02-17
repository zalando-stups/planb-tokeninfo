package jwthandler

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/rcrowley/go-metrics"
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
	start := time.Now()
	ti, err := h.validateToken(r)
	if err == nil && ti != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(ti); err != nil {
			fmt.Println("Error serializing the token info: ", err)
		} else {
			measureRequest(start, fmt.Sprintf("planb.tokeinfo.jwt.%s.requests", ti.Realm))
		}
		return
	}

	var tie tokeninfo.TokenInfoError
	switch err {
	case jwt.ErrNoTokenInRequest:
		tie = tokeninfo.ErrInvalidRequest
	default:
		tie = tokeninfo.ErrInvalidToken
	}
	registerError(tie)
	tokeninfo.Error(w, tie)
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
	start := time.Now()
	token, err := jwt.ParseFromRequest(req, jwtValidator(h.keyLoader))
	if err == nil {
		measureRequest(start, fmt.Sprintf("planb.tokeninfo.jwt.validation.%s", token.Method.Alg()))
	}
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

func measureRequest(start time.Time, key string) {
	t := metrics.DefaultRegistry.GetOrRegister(key, metrics.NewTimer).(metrics.Timer)
	t.UpdateSince(start)
}

func registerError(err tokeninfo.TokenInfoError) {
	key := fmt.Sprintf("planb.tokeninfo.jwt.errors.%s", err.Error)
	c := metrics.DefaultRegistry.GetOrRegister(key, metrics.NewCounter).(metrics.Counter)
	c.Inc(1)
}
