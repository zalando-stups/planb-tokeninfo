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

func hostModifier(upstreamUrl *url.URL, original func(req *http.Request)) func(req *http.Request) {
	return func(req *http.Request) {
		original(req)
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
	hystrix.Do("proxy", func() error {
		start := time.Now()
		h.upstream.ServeHTTP(w, req)
		t := metrics.DefaultRegistry.GetOrRegister("planb.tokeninfo.proxy", metrics.NewTimer).(metrics.Timer)
		t.UpdateSince(start)
		return nil
	}, nil)
}

func NewTokenInfoProxyHandler(url *url.URL) http.Handler {
	p := httputil.NewSingleHostReverseProxy(url)
	p.Director = hostModifier(url, p.Director)
	return &tokenInfoProxyHandler{upstream: p}
}
