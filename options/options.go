package options

import (
	"log"
	"net/url"
	"os"
	"strconv"
	"time"
)

const (
	defaultOpenIdProviderRefreshInterval = 30 * time.Second
	defaultHttpClientTimeout             = 10 * time.Second
	defaultHttpClientTlsTimeout          = 10 * time.Second
	defaultHttpClientKeepAlive           = 30 * time.Second
)

var (
	UpstreamTokenInfoUrl           *url.URL
	OpenIdProviderConfigurationUrl *url.URL
	OpenIdProviderRefreshInterval  time.Duration
	HttpClientTimeout              time.Duration
	HttpClientTlsTimeout           time.Duration
	HttpClientKeepAlive            time.Duration
)

func init() {
	url, err := getUrl("UPSTREAM_TOKENINFO_URL")
	if err != nil {
		log.Fatal("Error with the upstream url: ", err)
	}
	UpstreamTokenInfoUrl = url

	url, err = getUrl("OPENID_PROVIDER_CONFIGURATION_URL")
	if err != nil {
		log.Fatal("Error with the OpenID provider configuration url: ", err)
	}
	OpenIdProviderConfigurationUrl = url

	OpenIdProviderRefreshInterval = getDuration("OPENID_PROVIDER_REFRESH_INTERVAL", defaultOpenIdProviderRefreshInterval)
	HttpClientTimeout = getDuration("HTTP_CLIENT_TIMEOUT", defaultHttpClientTimeout)
	HttpClientTlsTimeout = getDuration("HTTP_CLIENT_TLS_TIMEOUT", defaultHttpClientTlsTimeout)
	HttpClientKeepAlive = getDuration("HTTP_CLIENT_KEEP_ALIVE", defaultHttpClientKeepAlive)
}

func getUrl(v string) (*url.URL, error) {
	return url.Parse(os.Getenv(v))
}

func getInt(v string, def int) int {
	i, err := strconv.Atoi(os.Getenv(v))
	if err != nil {
		return def
	}
	return i
}

func getDuration(v string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(os.Getenv(v))
	if err != nil {
		return def
	}
	return d
}
