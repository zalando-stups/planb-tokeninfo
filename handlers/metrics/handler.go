package metrics

import (
	"github.com/rcrowley/go-metrics"
	"net/http"
)

type metricsHandler struct {
	registry metrics.Registry
}

func (h *metricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	metrics.WriteJSONOnce(h.registry, w)
}

// NewHandler creates an http.Handler that returns metrics registry r serialized as JSON
func Handler(r metrics.Registry) http.Handler {
	return &metricsHandler{registry: r}
}
