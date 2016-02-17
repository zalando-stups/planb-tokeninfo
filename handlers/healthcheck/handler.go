package healthcheck

import "net/http"

type Handler string

const Default = Handler("OK")

// ServeHTTP returns a 200 status code and its own string representation in the response
func (h Handler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(h))
}
