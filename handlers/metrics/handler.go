package metrics

import (
	"net/http"

	"github.com/rcrowley/go-metrics"
)

type metricsHandler struct {
	registry metrics.Registry
}

// Default is a global instance of the metrics handler using the metrics default registry
var Default = Handler(metrics.DefaultRegistry)

// ServeHTTP returns status 200 and writes metrics from the registry as JSON
func (h *metricsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	metrics.WriteJSONOnce(h.registry, w)
}

// Handler creates an http.Handler that returns metrics registry r serialized as JSON
func Handler(r metrics.Registry) http.Handler {
	return &metricsHandler{registry: r}
}
