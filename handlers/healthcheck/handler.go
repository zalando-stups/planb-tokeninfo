package healthcheck

import "net/http"

type healthCheckHandler struct {
	response []byte
}

const defaultResponse = "OK"

func (h *healthCheckHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write(h.response)
}

// DefaultHandler creates an http.Handler that always returns "OK" in the response and 200 status code
func DefaultHandler() http.Handler {
	return NewHandler(defaultResponse)
}

// NewHandler creates an http.Handler that returns a 200 status code and the s in the response
func NewHandler(s string) http.Handler {
	return &healthCheckHandler{response: []byte(s)}
}
