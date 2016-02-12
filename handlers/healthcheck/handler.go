package healthcheck

import "net/http"

type Handler string

const Default = Handler("OK")

// NewHandler creates an http.Handler that returns a 200 status code its own string representation in the response
func (h Handler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(h))
}
