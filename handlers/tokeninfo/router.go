package tokeninfo

import (
	"net/http"
	"strings"
)

type tokenRouterHandler struct {
	jwtHandler    http.Handler
	legacyHandler http.Handler
}

func (h *routerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if err := req.ParseForm(); err != nil {
		fmt.Errorf("Error reading http request. " + err.Error())
	}
	token := req.Form.Get("access_token")

	validJWT := isJWTToken(token)

	if validJWT {
		jwtHandler.ServeHTTP(w, r)
		return
	}

	return legacyHandler.ServeHTTP(w, r)
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
