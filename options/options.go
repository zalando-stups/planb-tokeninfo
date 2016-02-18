package options

import (
	"log"
	"net/url"
	"os"
	"strconv"
	"time"
)

const (
	defaultListenAddr        = ":9021"
	defaultMetricsListenAddr = ":9020"

	defaultOpenIdProviderRefreshInterval = 30 * time.Second
	defaultHttpClientTimeout             = 10 * time.Second
	defaultHttpClientTlsTimeout          = 10 * time.Second
	defaultHttpClientKeepAlive           = 30 * time.Second
	defaultRevokeProviderRefreshInterval = 90 * time.Second
)

var (
	ListenAddress                     string
	MetricsListenAddress              string
	UpstreamTokenInfoUrl              *url.URL
	OpenIdProviderConfigurationUrl    *url.URL
	RevocationProviderUrl             *url.URL
	OpenIdProviderRefreshInterval     time.Duration
	HttpClientTimeout                 time.Duration
	HttpClientTlsTimeout              time.Duration
	HttpClientKeepAlive               time.Duration
	RevocationProviderRefreshInterval time.Duration
)

func LoadFromEnvironment() {
	ListenAddress = getString("LISTEN_ADDRESS", defaultListenAddr)
	MetricsListenAddress = getString("METRICS_LISTEN_ADDRESS", defaultMetricsListenAddr)

	url, err := getUrl("UPSTREAM_TOKENINFO_URL")
	if err != nil {
		log.Fatal("Error with the upstream url: ", err)
	}
	UpstreamTokenInfoUrl = url

	url, err = getUrl("OPENID_PROVIDER_CONFIGURATION_URL")
	if err != nil || url == nil {
		log.Fatal("Invalid OpenID provider configuration url: ", err)
	}
	if url.String() == "" {
		log.Fatal("Missing OpenID provider configuration url")
	}
	OpenIdProviderConfigurationUrl = url

	url, err = getUrl("REVOCATION_PROVIDER_URL")
	if err != nil || url == nil {
		log.Fatal("Invalid revocation provider URL")
	}
	RevocationProviderUrl = url

	OpenIdProviderRefreshInterval = getDuration("OPENID_PROVIDER_REFRESH_INTERVAL", defaultOpenIdProviderRefreshInterval)
	HttpClientTimeout = getDuration("HTTP_CLIENT_TIMEOUT", defaultHttpClientTimeout)
	HttpClientTlsTimeout = getDuration("HTTP_CLIENT_TLS_TIMEOUT", defaultHttpClientTlsTimeout)
	HttpClientKeepAlive = getDuration("HTTP_CLIENT_KEEP_ALIVE", defaultHttpClientKeepAlive)
	RevocationProviderRefreshInterval = getDuration("REVOCATION_PROVIDER_REFRESH_INTERVAL", defaultRevokeProviderRefreshInterval)
}

func getString(v string, def string) string {
	if s := os.Getenv(v); s != "" {
		return s
	}
	return def
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
