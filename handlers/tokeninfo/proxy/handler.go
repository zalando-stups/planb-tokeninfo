package tokeninfoproxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/afex/hystrix-go/hystrix"
	"github.com/rcrowley/go-metrics"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo"
	"time"
)

type tokenInfoProxyHandler struct {
	upstream *httputil.ReverseProxy
}

// NewTokenInfoProxyHandler returns an http.Handler that proxies every Request to the server
// at the upstreamURL
func NewTokenInfoProxyHandler(upstreamURL *url.URL) http.Handler {
	p := httputil.NewSingleHostReverseProxy(upstreamURL)
	p.Director = hostModifier(upstreamURL, p.Director)
	return &tokenInfoProxyHandler{upstream: p}
}

// ServeHTTP proxies the Request with an Access Token to the upstream and sends back the response
// from the upstream
func (h *tokenInfoProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	token := tokeninfo.AccessTokenFromRequest(req)
	if token == "" {
		tokeninfo.WriteError(w, tokeninfo.ErrInvalidRequest)
		return
	}
	hystrix.Do("proxy", func() error {
		start := time.Now()
		h.upstream.ServeHTTP(w, req)
		t := metrics.DefaultRegistry.GetOrRegister("planb.tokeninfo.proxy", metrics.NewTimer).(metrics.Timer)
		t.UpdateSince(start)
		return nil
	}, nil)
}

func hostModifier(upstreamURL *url.URL, original func(req *http.Request)) func(req *http.Request) {
	return func(req *http.Request) {
		original(req)
		req.Host = upstreamURL.Host
		req.URL.Path = upstreamURL.Path
	}
}
