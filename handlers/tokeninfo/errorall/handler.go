package errorall

import (
	"fmt"
	"net/http"

	"github.com/rcrowley/go-metrics"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo"
)

type errorAllHandler struct{}

// NewErrorAllHandler returns an http.Handler that returns an error on every request
func NewErrorAllHandler() http.Handler {
	return &errorAllHandler{}
}

// ServeHTTP returns an error for all requests
func (h *errorAllHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var tie tokeninfo.Error
	if tokeninfo.AccessTokenFromRequest(req) == "" {
		tie = tokeninfo.ErrInvalidRequest
	} else {
		tie = tokeninfo.ErrInvalidToken
	}
	registerError(tie)
	tie.Write(w)
	return
}

func registerError(err tokeninfo.Error) {
	key := fmt.Sprintf("planb.tokeninfo.nonjwt.errors.%s", err.Error)
	if c, ok := metrics.DefaultRegistry.GetOrRegister(key, metrics.NewCounter).(metrics.Counter); ok {
		c.Inc(1)
	}
}
