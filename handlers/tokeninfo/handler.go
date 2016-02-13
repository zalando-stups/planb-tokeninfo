package tokeninfo

import (
	"net/http"
	"strings"
)

const ACCESS_TOKEN_PARAMETER = "access_token"

type TokenInfoHandler interface {
	http.Handler
	Match(r *http.Request) bool
}

type routingHandler struct {
	defaultHandler http.Handler
	routes         []TokenInfoHandler
}

func Handler(def http.Handler, r ...TokenInfoHandler) http.Handler {
	return &routingHandler{defaultHandler: def, routes: r}
}

func (rh *routingHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if h := rh.matchRequest(req); h != nil {
		h.ServeHTTP(w, req)
	} else {
		rh.defaultHandler.ServeHTTP(w, req)
	}
}

func (rh *routingHandler) matchRequest(r *http.Request) http.Handler {
	for _, h := range rh.routes {
		if h.Match(r) {
			return h
		}
	}
	return nil
}

// https://tools.ietf.org/html/rfc6749#section-5.1
// https://tools.ietf.org/html/rfc6750#section-2.1
func AccessTokenFromRequest(req *http.Request) string {
	if h := req.Header.Get("Authorization"); h != "" {
		if strings.HasPrefix(strings.ToLower(h), "bearer ") {
			return h[7:]
		}
	}

	return req.FormValue(ACCESS_TOKEN_PARAMETER)
}
