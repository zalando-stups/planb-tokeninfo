package tokeninfo

import (
	"net/http"
    "os"
	"io/ioutil"
)

type legacyTokenHandler struct {
}

func (h *legacyTokenHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	if err := req.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
	}
	token := req.Form.Get("access_token")

    url := os.Getenv("TOKENINFO_LEGACY_URL")
	resp, err := http.Get(url + token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	w.Write(body)
}
func DefaultLegacyTokenHandler() http.Handler {
	return NewLegacyTokenHandler()
}

func NewLegacyTokenHandler() http.Handler {
	return &legacyTokenHandler{}
}
