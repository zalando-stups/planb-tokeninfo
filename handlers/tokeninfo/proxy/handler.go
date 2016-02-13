package tokeninfoproxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo"
)

type tokenInfoProxyHandler struct {
	upstream *httputil.ReverseProxy
}

func (h *tokenInfoProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	token := req.URL.Query().Get("access_token")
	if token == "" {
		tokeninfo.Error(w, tokeninfo.ErrInvalidRequest)
		return
	}
	h.upstream.ServeHTTP(w, req)
}

func NewTokenInfoProxyHandler(url *url.URL) http.Handler {
	return &tokenInfoProxyHandler{upstream: httputil.NewSingleHostReverseProxy(url)}
}
