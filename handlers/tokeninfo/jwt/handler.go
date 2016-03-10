package jwthandler

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/rcrowley/go-metrics"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo"
	"github.com/zalando/planb-tokeninfo/keyloader"
	"github.com/zalando/planb-tokeninfo/revoke"
)

type jwtHandler struct {
	keyLoader keyloader.KeyLoader
	crp       *revoke.CachingRevokeProvider
}

// New returns an http.Handler that is able to validate JWT tokens
func New(kl keyloader.KeyLoader, crp *revoke.CachingRevokeProvider) tokeninfo.Handler {
	return &jwtHandler{keyLoader: kl, crp: crp}
}

// ServeHTTP will validate the JWT token in the Request and send back the TokenInfo in case
// of success or the appropriate error messages otherwise. Both are sent in JSON.
func (h *jwtHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ti, err := h.validateToken(r)
	if err == nil && ti != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := ti.Marshal(w); err != nil {
			fmt.Println("Error serializing the token info: ", err)
		} else {
			measureRequest(start, fmt.Sprintf("planb.tokeninfo.jwt.%s.requests", ti.Realm))
		}
		return
	}

	var tie tokeninfo.Error
	switch err {
	case jwt.ErrNoTokenInRequest:
		tie = tokeninfo.ErrInvalidRequest
	default:
		tie = tokeninfo.ErrInvalidToken
	}
	registerError(tie)
	tie.Write(w)
}

func (h *jwtHandler) validateToken(req *http.Request) (*TokenInfo, error) {
	start := time.Now()
	token, err := jwt.ParseFromRequest(req, jwtValidator(h.keyLoader))
	if err == nil {
		measureRequest(start, fmt.Sprintf("planb.tokeninfo.jwt.validation.%s", token.Method.Alg()))
	}
	if err == nil && token.Valid && !h.crp.IsJWTRevoked(token) {
		return newTokenInfo(token, time.Now())
	}
	log.Println("Failed to validate token: ", err)
	return nil, err
}

// Checks if the Request contains a JWT that can be handled by this Handler
func (h *jwtHandler) Match(r *http.Request) bool {
	token := tokeninfo.AccessTokenFromRequest(r)
	if token == "" {
		return false
	}

	parts := strings.Split(token, ".")

	return len(parts) == 3
}

func measureRequest(start time.Time, key string) {
	if t, ok := metrics.DefaultRegistry.GetOrRegister(key, metrics.NewTimer).(metrics.Timer); ok {
		t.UpdateSince(start)
	}
}

func registerError(err tokeninfo.Error) {
	key := fmt.Sprintf("planb.tokeninfo.jwt.errors.%s", err.Error)
	if c, ok := metrics.DefaultRegistry.GetOrRegister(key, metrics.NewCounter).(metrics.Counter); ok {
		c.Inc(1)
	}
}
