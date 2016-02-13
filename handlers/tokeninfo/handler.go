package tokeninfo

import (
	"net/http"
)

type TokenInfoHandler interface {
	http.Handler
	Match(r *http.Request) bool
}

type routingHandler struct {
	defaultHandler http.Handler
	routes         []TokenInfoHandler
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

func Handler(def http.Handler, r ...TokenInfoHandler) http.Handler {
	return &routingHandler{defaultHandler: def, routes: r}
}
