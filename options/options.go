package options

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"
)

// The Settings type contains the application configurable options
type Settings struct {
	ListenAddress                  string
	MetricsListenAddress           string
	UpstreamTokenInfoURL           *url.URL
	OpenIDProviderConfigurationURL *url.URL
	OpenIDProviderRefreshInterval  time.Duration
	HTTPClientTimeout              time.Duration
	HTTPClientTLSTimeout           time.Duration
}

const (
	defaultListenAddress                 = ":9021"
	defaultMetricsListenAddress          = ":9020"
	defaultOpenIDRefreshInterval         = 30 * time.Second
	defaultHTTPClientTimeout             = 10 * time.Second
	defaultHTTPClientTLSTimeout          = 10 * time.Second
	defaultRevokeProviderRefreshInterval = 90 * time.Second
	defaultRevokeExpireLength            = 8 * 60 * time.Second

	defaultHashingSalt = "seasaltisthebest"
)

var (
	// AppSettings is a global variable that holds the application settings
	AppSettings = defaultSettings()
)

func defaultSettings() *Settings {
	return &Settings{
		ListenAddress:                 defaultListenAddress,
		MetricsListenAddress:          defaultMetricsListenAddress,
		OpenIDProviderRefreshInterval: defaultOpenIDRefreshInterval,
		HTTPClientTimeout:             defaultHTTPClientTimeout,
		HTTPClientTLSTimeout:          defaultHTTPClientTLSTimeout,
	}
}

// LoadFromEnvironment will try to load all the options from environment variables.
// It will return an error if the required options are not available. The required environment
// variables are:
//
//      UPSTREAM_TOKENINFO_URL
//      OPENID_PROVIDER_CONFIGURATION_URL
//
// The remaining options have sane defaults and are not mandatory
func LoadFromEnvironment() error {
	settings := defaultSettings()
	url, err := getURL("UPSTREAM_TOKENINFO_URL")
	if err != nil {
		return fmt.Errorf("Error with UPSTREAM_TOKENINFO_URL: %v\n", err)
	}
	settings.UpstreamTokenInfoURL = url

	url, err = getURL("OPENID_PROVIDER_CONFIGURATION_URL")
	if err != nil || url == nil {
		return fmt.Errorf("Invalid OPENID_PROVIDER_CONFIGURATION_URL: %v\n", err)
	}
	settings.OpenIDProviderConfigurationURL = url

	if s := getString("LISTEN_ADDRESS", ""); s != "" {
		settings.ListenAddress = s
	}

	if s := getString("METRICS_LISTEN_ADDRESS", ""); s != "" {
		settings.MetricsListenAddress = s
	}

	if d := getDuration("OPENID_PROVIDER_REFRESH_INTERVAL", 0); d > 0 {
		settings.OpenIDProviderRefreshInterval = d
	}

	if d := getDuration("HTTP_CLIENT_TIMEOUT", 0); d > 0 {
		settings.HTTPClientTimeout = d
	}

	if d := getDuration("HTTP_CLIENT_TLS_TIMEOUT", 0); d > 0 {
		settings.HTTPClientTLSTimeout = d
	}
	AppSettings = settings
	return nil
}

func getString(v string, def string) string {
	s, ok := os.LookupEnv(v)
	if !ok {
		return def
	}
	return s
}

func getURL(v string) (*url.URL, error) {
	u, ok := os.LookupEnv(v)
	if !ok || u == "" {
		return nil, fmt.Errorf("Missing URL setting: %q", v)
	}
	return url.Parse(u)
}

func getInt(v string, def int) int {
	s, ok := os.LookupEnv(v)
	if !ok {
		return def
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return i
}

func getDuration(v string, def time.Duration) time.Duration {
	s, ok := os.LookupEnv(v)
	if !ok || s == "" {
		return def
	}

	if d, err := time.ParseDuration(s); err == nil {
		return d
	}

	if seconds, err := strconv.Atoi(s); err == nil {
		return time.Duration(seconds) * time.Second
	}

	return def
}
