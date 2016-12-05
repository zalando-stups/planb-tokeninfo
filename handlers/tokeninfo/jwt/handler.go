package jwthandler

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo"
	"github.com/zalando/planb-tokeninfo/keyloader"
	"github.com/zalando/planb-tokeninfo/revoke"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/zalando/planb-tokeninfo/processor"
)

type jwtHandler struct {
	keyLoader keyloader.KeyLoader
	crp       *revoke.CachingRevokeProvider
}

var (
	ErrInvalidJWT   = errors.New("Invalid JWT token.")
	ErrRevokedToken = errors.New("Token is revoked.")
)

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
		if err := Marshal(ti, w); err != nil {
			fmt.Println("Error serializing the token info: ", err)
		} else {
			measureRequest(start, fmt.Sprintf("planb.tokeninfo.jwt.%s.requests", ti.Realm))
		}
		return
	}

	var tie tokeninfo.Error
	switch err {
	case request.ErrNoTokenInRequest:
		tie = tokeninfo.ErrInvalidRequest
	default:
		tie = tokeninfo.ErrInvalidToken
	}
	registerError(tie)
	tie.Write(w)
}

func (h *jwtHandler) validateToken(req *http.Request) (*processor.TokenInfo, error) {
	start := time.Now()
	token, err := request.ParseFromRequest(req, request.OAuth2Extractor, jwtValidator(h.keyLoader))
	if err != nil {
		log.Println("Failed to validate token: ", err)
		return nil, err
	}

	measureRequest(start, fmt.Sprintf("planb.tokeninfo.jwt.validation.%s", token.Method.Alg()))
	if !token.Valid {
		log.Println("Failed to validate token: ", ErrInvalidJWT)
		return nil, ErrInvalidJWT
	}
	if h.crp.IsJWTRevoked(token) {
		log.Println("Failed to validate token: ", ErrRevokedToken)
		return nil, ErrRevokedToken
	}
	return NewTokenInfo(token, time.Now())
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
