package errorall

import (
	"net/http"

	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo"
)

type errorAllHandler struct{}

// NewErrorAllHandler returns an http.Handler that returns an error on every request
func NewErrorAllHandler() http.Handler {
	return &errorAllHandler{}
}

// ServeHTTP returns an error for all requests
func (h *errorAllHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if tokeninfo.AccessTokenFromRequest(req) == "" {
		tokeninfo.ErrInvalidRequest.Write(w)
		return
	}
	tokeninfo.ErrInvalidToken.Write(w)
	return
}
