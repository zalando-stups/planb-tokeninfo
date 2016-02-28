package tokeninfoproxy

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/afex/hystrix-go/hystrix"
	"github.com/karlseguin/ccache"
	"github.com/rcrowley/go-metrics"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo"
	"time"
)

type tokenInfoProxyHandler struct {
	upstream *httputil.ReverseProxy
	cache    *ccache.Cache
	cacheTTL time.Duration
}

// NewTokenInfoProxyHandler returns an http.Handler that proxies every Request to the server
// at the upstreamURL
func NewTokenInfoProxyHandler(upstreamURL *url.URL, cacheMaxSize int64, cacheTTL time.Duration) http.Handler {
	log.Printf("Upstream tokeninfo is %s with %v cache (%d max size)", upstreamURL, cacheTTL, cacheMaxSize)
	p := httputil.NewSingleHostReverseProxy(upstreamURL)
	p.Director = hostModifier(upstreamURL, p.Director)
	cache := ccache.New(ccache.Configure().MaxSize(cacheMaxSize))
	return &tokenInfoProxyHandler{upstream: p, cache: cache, cacheTTL: cacheTTL}
}

func newResponseBuffer(w http.ResponseWriter) *responseBuffer {
	return &responseBuffer{
		ResponseWriter: w,
		Buffer:         &bytes.Buffer{},
	}
}

type responseBuffer struct {
	http.ResponseWriter
	Buffer     *bytes.Buffer
	StatusCode int
}

func (rw *responseBuffer) WriteHeader(status int) {
	rw.StatusCode = status
	rw.ResponseWriter.WriteHeader(status)
}

func (rw *responseBuffer) Write(b []byte) (int, error) {
	rw.Buffer.Write(b)
	return rw.ResponseWriter.Write(b)
}

// ServeHTTP proxies the Request with an Access Token to the upstream and sends back the response
// from the upstream
func (h *tokenInfoProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	token := tokeninfo.AccessTokenFromRequest(req)
	if token == "" {
		tokeninfo.ErrInvalidRequest.Write(w)
		return
	}
	item := h.cache.Get(token)
	if item != nil {
		if !item.Expired() {
			w.Header().Set("Content-Type", "application/json;charset=UTF-8")
			w.Header().Set("X-Cache", "HIT")
			w.Write(item.Value().([]byte))
			return
		}
	}
	hystrix.Do("proxy", func() error {
		start := time.Now()
		rw := newResponseBuffer(w)
		rw.Header().Set("X-Cache", "MISS")
		h.upstream.ServeHTTP(rw, req)
		if rw.StatusCode == 200 {
			h.cache.Set(token, rw.Buffer.Bytes(), h.cacheTTL)
		}
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
