package breaker

import (
	"github.com/zalando/planb-tokeninfo/options"
	"net"
	"net/http"
	"time"
)

var Default = DefaultHttpClient()

func DefaultHttpClient() *http.Client {
	return NewHttpClient(options.HttpClientTimeout, options.HttpClientTlsTimeout, options.HttpClientKeepAlive)
}

// NewHttpClient returns an http.Client that uses the timeouts from its arguments and, more importantly, it disables
// KeepAlive. That means no connection pooling. Use it only for one time requests where performance is not a concern
func NewHttpClient(timeout time.Duration, tlsTimeout time.Duration, keepAlive time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:             http.ProxyFromEnvironment,
			DisableKeepAlives: true,
			Dial: (&net.Dialer{
				Timeout:   options.HttpClientTimeout,
				KeepAlive: keepAlive}).Dial,
			TLSHandshakeTimeout: tlsTimeout}}
}

func Get(url string) (*http.Response, error) {
	return Default.Get(url)
}
