package tokeninfoproxy

import (
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo"
	"net/http"
	"net/http/httputil"
	"net/url"
)

type tokenInfoProxyHandler struct {
	upstream *httputil.ReverseProxy
}

func hostModifier(upstreamUrl *url.URL, original func(req *http.Request)) func(req *http.Request) {
	return func(req *http.Request) {
		original(req)
		// request upstream tokeninfo with correct host and path
		// (httputil.ReverseProxy would otherwise concatenate paths)
		req.Host = upstreamUrl.Host
		req.URL.Path = upstreamUrl.Path
	}
}

func (h *tokenInfoProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	token := tokeninfo.AccessTokenFromRequest(req)
	if token == "" {
		tokeninfo.Error(w, tokeninfo.ErrInvalidRequest)
		return
	}
	h.upstream.ServeHTTP(w, req)
}

func NewTokenInfoProxyHandler(url *url.URL) http.Handler {
	p := httputil.NewSingleHostReverseProxy(url)
	p.Director = hostModifier(url, p.Director)
	return &tokenInfoProxyHandler{upstream: p}
}
