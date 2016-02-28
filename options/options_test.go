package options

import (
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestGetString(t *testing.T) {
	for _, test := range []struct {
		envSet string
		envGet string
		value  string
		def    string
		want   string
	}{
		{"T1", "T1", "to-be", "or-not", "to-be"},
		{"", "T2", "", "default", "default"},
		{"T3", "SHOULD_NOT_BE_FOUND_IN_ENV", "foo", "bar", "bar"},
	} {
		os.Clearenv()
		if test.envSet != "" {
			os.Setenv(test.envSet, test.value)
		}
		if s := getString(test.envGet, test.def); s != test.want {
			t.Errorf("Failed to retrieve the correct value from the environment. Wanted %q, got %q", test.want, s)
		}
	}
}

func TestGetUrl(t *testing.T) {
	for _, test := range []struct {
		name      string
		value     string
		want      string
		wantError bool
	}{
		{"", "localhost", "", true},
		{"DIFFICULT_TO_GUESS", "localhost", "localhost", false},
		{"DIFFICULT_TO_GUESS", "http://192.168.0.%31/", "", true},
		{"DIFFICULT_TO_GUESS", "", "", true},
		{"DIFFICULT_TO_GUESS", "http://example.com", "http://example.com", false},
	} {
		os.Clearenv()
		if test.name != "" {
			os.Setenv(test.name, test.value)
		}
		u, err := getURL(test.name)
		if test.wantError {
			if err == nil {
				t.Error("Expected an error but call succeeded: ", test)
			}
		} else {
			if u.String() != test.want {
				t.Errorf("Unexpected URL. Wanted %q, got %v", test.want, u)
			}
		}
	}
}

func TestGetInt(t *testing.T) {
	for _, test := range []struct {
		envSet string
		value  string
		envGet string
		def    int
		want   int
	}{
		{"T1", "", "T1", 42, 42},
		{"T1", "invalid-int", "T1", 15, 15},
		{"", "", "DIFFICULT_TO_GUESS", 0, 0},
		{"T1", "7", "T1", 0, 7},
	} {
		os.Clearenv()
		if test.envSet != "" {
			os.Setenv(test.envSet, test.value)
		}
		if s := getInt(test.envGet, test.def); s != test.want {
			t.Errorf("Failed to retrieve the correct value from the environment. Wanted %q, got %q", test.want, s)
		}
	}
}

func TestGetDuration(t *testing.T) {
	for _, test := range []struct {
		envSet string
		value  string
		envGet string
		def    time.Duration
		want   time.Duration
	}{
		{"T1", "", "T1", time.Millisecond, time.Millisecond},
		{"T1", "invalid-duration", "T1", time.Second, time.Second},
		{"", "", "DIFFICULT_TO_GUESS", 0, 0},
		{"T1", "7ns", "T1", 0, 7},
		{"T1", "7ms", "T1", 0, 7 * time.Millisecond},
		{"T1", "30s", "T1", 0, 30 * time.Second},
		{"T1", "30m", "T1", 0, 30 * time.Minute},
		{"T1", "1h", "T1", 0, time.Hour},
		{"T1", "10", "T1", 0, 10 * time.Second},
	} {
		os.Clearenv()
		if test.envSet != "" {
			os.Setenv(test.envSet, test.value)
		}
		if s := getDuration(test.envGet, test.def); s != test.want {
			t.Errorf("Failed to retrieve the correct value from the environment. Wanted %q, got %q", test.want, s)
		}
	}
}

func TestLoading(t *testing.T) {
	exampleCom, _ := url.Parse("http://example.com")
	for _, test := range []struct {
		env      map[string]string
		want     *Settings
		wantFail bool
	}{
		{map[string]string{}, nil, true},
		{
			map[string]string{"UPSTREAM_TOKENINFO_URL": ""},
			nil,
			true,
		},
		{
			map[string]string{"UPSTREAM_TOKENINFO_URL": "http://example.com"},
			nil,
			true,
		},
		{
			map[string]string{
				"OPENID_PROVIDER_CONFIGURATION_URL": "http://example.com",
			},
			nil,
			true,
		},
		{
			map[string]string{
				"OPENID_PROVIDER_CONFIGURATION_URL": "",
			},
			nil,
			true,
		},
		{
			map[string]string{
				"UPSTREAM_TOKENINFO_URL":            "",
				"OPENID_PROVIDER_CONFIGURATION_URL": "",
			},
			nil,
			true,
		},
		{
			map[string]string{
				"UPSTREAM_TOKENINFO_URL":            "",
				"OPENID_PROVIDER_CONFIGURATION_URL": "http://example.com",
			},
			nil,
			true,
		},
		{
			map[string]string{
				"UPSTREAM_TOKENINFO_URL":            "http://example.com",
				"OPENID_PROVIDER_CONFIGURATION_URL": "",
			},
			nil,
			true,
		},
		{
			map[string]string{
				"UPSTREAM_TOKENINFO_URL":            "http://example.com",
				"OPENID_PROVIDER_CONFIGURATION_URL": "http://example.com",
			},
			&Settings{
				UpstreamTokenInfoURL:           exampleCom,
				OpenIDProviderConfigurationURL: exampleCom,
				UpstreamCacheMaxSize:           defaultUpstreamCacheMaxSize,
				UpstreamCacheTTL:               defaultUpstreamCacheTTL,
				HTTPClientTimeout:              defaultHTTPClientTimeout,
				HTTPClientTLSTimeout:           defaultHTTPClientTLSTimeout,
				OpenIDProviderRefreshInterval:  defaultOpenIDRefreshInterval,
				ListenAddress:                  defaultListenAddress,
				MetricsListenAddress:           defaultMetricsListenAddress,
			},
			false,
		},
		{
			map[string]string{
				"UPSTREAM_TOKENINFO_URL":            "http://example.com",
				"OPENID_PROVIDER_CONFIGURATION_URL": "http://example.com",
				"LISTEN_ADDRESS":                    ":80",
			},
			&Settings{
				UpstreamTokenInfoURL:           exampleCom,
				OpenIDProviderConfigurationURL: exampleCom,
				UpstreamCacheMaxSize:           defaultUpstreamCacheMaxSize,
				UpstreamCacheTTL:               defaultUpstreamCacheTTL,
				HTTPClientTimeout:              defaultHTTPClientTimeout,
				HTTPClientTLSTimeout:           defaultHTTPClientTLSTimeout,
				OpenIDProviderRefreshInterval:  defaultOpenIDRefreshInterval,
				ListenAddress:                  ":80",
				MetricsListenAddress:           defaultMetricsListenAddress,
			},
			false,
		},
		{
			map[string]string{
				"UPSTREAM_TOKENINFO_URL":            "http://example.com",
				"OPENID_PROVIDER_CONFIGURATION_URL": "http://example.com",
				"METRICS_LISTEN_ADDRESS":            ":80",
			},
			&Settings{
				UpstreamTokenInfoURL:           exampleCom,
				OpenIDProviderConfigurationURL: exampleCom,
				UpstreamCacheMaxSize:           defaultUpstreamCacheMaxSize,
				UpstreamCacheTTL:               defaultUpstreamCacheTTL,
				HTTPClientTimeout:              defaultHTTPClientTimeout,
				HTTPClientTLSTimeout:           defaultHTTPClientTLSTimeout,
				OpenIDProviderRefreshInterval:  defaultOpenIDRefreshInterval,
				ListenAddress:                  defaultListenAddress,
				MetricsListenAddress:           ":80",
			},
			false,
		},
		{
			map[string]string{
				"UPSTREAM_TOKENINFO_URL":            "http://example.com",
				"OPENID_PROVIDER_CONFIGURATION_URL": "http://example.com",
				"OPENID_PROVIDER_REFRESH_INTERVAL":  "1m",
			},
			&Settings{
				UpstreamTokenInfoURL:           exampleCom,
				OpenIDProviderConfigurationURL: exampleCom,
				UpstreamCacheMaxSize:           defaultUpstreamCacheMaxSize,
				UpstreamCacheTTL:               defaultUpstreamCacheTTL,
				HTTPClientTimeout:              defaultHTTPClientTimeout,
				HTTPClientTLSTimeout:           defaultHTTPClientTLSTimeout,
				OpenIDProviderRefreshInterval:  time.Minute,
				ListenAddress:                  defaultListenAddress,
				MetricsListenAddress:           defaultMetricsListenAddress,
			},
			false,
		},
		{
			map[string]string{
				"UPSTREAM_TOKENINFO_URL":            "http://example.com",
				"OPENID_PROVIDER_CONFIGURATION_URL": "http://example.com",
				"HTTP_CLIENT_TIMEOUT":               "1ms",
			},
			&Settings{
				UpstreamTokenInfoURL:           exampleCom,
				OpenIDProviderConfigurationURL: exampleCom,
				UpstreamCacheMaxSize:           defaultUpstreamCacheMaxSize,
				UpstreamCacheTTL:               defaultUpstreamCacheTTL,
				HTTPClientTimeout:              time.Millisecond,
				HTTPClientTLSTimeout:           defaultHTTPClientTLSTimeout,
				OpenIDProviderRefreshInterval:  defaultOpenIDRefreshInterval,
				ListenAddress:                  defaultListenAddress,
				MetricsListenAddress:           defaultMetricsListenAddress,
			},
			false,
		},
		{
			map[string]string{
				"UPSTREAM_TOKENINFO_URL":            "http://example.com",
				"UPSTREAM_CACHE_MAX_SIZE":           "123456789",
				"UPSTREAM_CACHE_TTL":                "17s",
				"OPENID_PROVIDER_CONFIGURATION_URL": "http://example.com",
				"HTTP_CLIENT_TLS_TIMEOUT":           "10ms",
			},
			&Settings{
				UpstreamTokenInfoURL:           exampleCom,
				OpenIDProviderConfigurationURL: exampleCom,
				UpstreamCacheMaxSize:           123456789,
				UpstreamCacheTTL:               17 * time.Second,
				HTTPClientTimeout:              defaultHTTPClientTimeout,
				HTTPClientTLSTimeout:           10 * time.Millisecond,
				OpenIDProviderRefreshInterval:  defaultOpenIDRefreshInterval,
				ListenAddress:                  defaultListenAddress,
				MetricsListenAddress:           defaultMetricsListenAddress,
			},
			false,
		},
		{
			map[string]string{
				"UPSTREAM_TOKENINFO_URL":            "http://example.com",
				"UPSTREAM_CACHE_MAX_SIZE":           "0",
				"UPSTREAM_CACHE_TTL":                "0",
				"OPENID_PROVIDER_CONFIGURATION_URL": "http://example.com",
				"HTTP_CLIENT_TLS_TIMEOUT":           "10ms",
			},
			&Settings{
				UpstreamTokenInfoURL:           exampleCom,
				OpenIDProviderConfigurationURL: exampleCom,
				UpstreamCacheMaxSize:           0,
				UpstreamCacheTTL:               0,
				HTTPClientTimeout:              defaultHTTPClientTimeout,
				HTTPClientTLSTimeout:           10 * time.Millisecond,
				OpenIDProviderRefreshInterval:  defaultOpenIDRefreshInterval,
				ListenAddress:                  defaultListenAddress,
				MetricsListenAddress:           defaultMetricsListenAddress,
			},
			false,
		},
	} {
		os.Clearenv()
		for k, v := range test.env {
			os.Setenv(k, v)
		}
		err := LoadFromEnvironment()
		if test.wantFail {
			if err == nil {
				t.Error("Wanted failure to load settings but it seems that it succeeded: ", test)
			}
		} else {
			if !reflect.DeepEqual(AppSettings, test.want) {
				t.Errorf("Settings mismatch.\nWanted %v\nGot %v", test.want, AppSettings)
			}
		}
	}
}
