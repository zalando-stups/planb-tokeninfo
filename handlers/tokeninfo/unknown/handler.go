package unknownhandler

import (
	"fmt"
	"net/http"

	"github.com/rcrowley/go-metrics"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo"
)

type unknownHandler struct{}

// New returns an http.Handler that is able to validate JWT tokens
func New() http.Handler {
	return &unknownHandler{}
}

// ServeHTTP will validate the JWT token in the Request and send back the TokenInfo in case
// of success or the appropriate error messages otherwise. Both are sent in JSON.
func (h *unknownHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	registerError(tokeninfo.ErrInvalidToken)
	tokeninfo.ErrInvalidToken.Write(w)
}

func registerError(err tokeninfo.Error) {
	key := fmt.Sprintf("planb.tokeninfo.unknown.errors.%s", err.Error)
	if c, ok := metrics.DefaultRegistry.GetOrRegister(key, metrics.NewCounter).(metrics.Counter); ok {
		c.Inc(1)
	}
}
