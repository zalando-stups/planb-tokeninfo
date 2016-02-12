package tokeninfo

import (
	"net/http"
	"strings"
)

type tokenRouterHandler struct {
	jwtHandler    http.Handler
	legacyHandler http.Handler
}

func (h *tokenRouterHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	// TODO: read query param and Authorization header
	if err := req.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)

	}
	token := req.Form.Get("access_token")

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
