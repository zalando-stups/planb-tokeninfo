package tokeninfo

import (
	"net/http"
	"strings"
)

const accessTokenParameter = "access_token"

// A Handler is a regular http.Handler that can be queried for its capacity of handling a
// Request. The Match function should be as fast as possible verifying if the Request matches
type Handler interface {
	http.Handler
	Match(r *http.Request) bool
}

type routingHandler struct {
	defaultHandler http.Handler
	routes         []Handler
}

// NewHandler returns an http.Handler that contains a default http.Handler and a variadic argument
// of TokenInfoHandlers that will selectively handle specific requests
func NewHandler(def http.Handler, r ...Handler) http.Handler {
	return &routingHandler{defaultHandler: def, routes: r}
}

// ServeHTTP will go through the list of TokenInfoHandlers and test for a match for the current Request.
// The first TokenInfoHandler to match will handle the request.
// If none of them can handle the request, it is handled by the default Handler
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

// AccessTokenFromRequest can be used to extract an Access Token from an http.Request
// via the standard headers/parameters
//  Ref:
//      https://tools.ietf.org/html/rfc6749#section-5.1
//      https://tools.ietf.org/html/rfc6750#section-2.1
func AccessTokenFromRequest(req *http.Request) string {
	if h := req.Header.Get("Authorization"); h != "" {
		if strings.HasPrefix(strings.ToLower(h), "bearer ") {
			return h[7:]
		}
	}

	return req.FormValue(accessTokenParameter)
}
