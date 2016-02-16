package breaker

import (
	"net"
	"net/http"
	"time"
)

var defaultClient *http.Client

func init() {
	t := http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 50 * time.Second,
		DisableKeepAlives:   true,
	}
	defaultClient = &http.Client{Transport: &t}
}

func Get(url string) (*http.Response, error) {
	return defaultClient.Get(url)
}
