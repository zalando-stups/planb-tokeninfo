package healthcheck

import (
	"fmt"
	"net/http"

	"github.com/zalando/planb-tokeninfo/keyloader"
)

type handler struct {
	ver    string
	loader keyloader.KeyLoader
}

// NewHandler creates an Health check http.Handler that returns 200 when there is at least 1 key
// Response also reports version
func NewHandler(kl keyloader.KeyLoader, version string) http.Handler {
	return &handler{loader: kl, ver: version}
}

// ServeHTTP returns a 200 status code if there is at least 1 key available or 503 otherwise
func (h handler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	if len(h.loader.Keys()) < 1 {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "No keys available\n%s", h.ver)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "OK\n%s", h.ver)
	}
}
