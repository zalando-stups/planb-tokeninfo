package tokeninfo

import (
	"errors"
	"net/http"
	"strings"
)

var (
	ErrNoTokenInRequest = errors.New("no token present in request")
)

type tokenRouterHandler struct {
	jwtHandler    http.Handler
	legacyHandler http.Handler
}

// snippet stolen from https://github.com/dgrijalva/jwt-go/blob/master/token.go
// Try to find the token in an http.Request.
// This method will call ParseMultipartForm if there's no token in the header.
// Currently, it looks in the Authorization header as well as
// looking for an 'access_token' request parameter in req.Form.
func parseFromRequest(req *http.Request) (token string, err error) {

	// Look for an Authorization header
	if ah := req.Header.Get("Authorization"); ah != "" {
		// Should be a bearer token
		if len(ah) > 6 && strings.ToUpper(ah[0:7]) == "BEARER " {
			return ah[7:], nil
		}
	}

	// Look for "access_token" parameter
	req.ParseMultipartForm(10e6)
	if tokStr := req.Form.Get("access_token"); tokStr != "" {
		return tokStr, nil
	}

	return "", ErrNoTokenInRequest
}

func (h *tokenRouterHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	token, err := parseFromRequest(req)
	if err != nil {
		writeError(w, "invalid_request", err.Error())
		return
	}

	validJWT := isJWTToken(token)

	if validJWT {
		h.jwtHandler.ServeHTTP(w, req)
		return
	}

	h.legacyHandler.ServeHTTP(w, req)
}

func DefaultTokenRouterHandler() http.Handler {
	return &tokenRouterHandler{jwtHandler: DefaultTokenInfoHandler(), legacyHandler: DefaultTokenInfoHandler()}
}

func isJWTToken(token string) bool {

	parts := strings.Split(token, ".")
	if len(parts) < 3 {
		return false
	}

	return true
}
