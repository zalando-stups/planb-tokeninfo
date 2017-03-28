package runner

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	gometrics "github.com/rcrowley/go-metrics"
	"github.com/zalando/planb-tokeninfo/handlers/healthcheck"
	"github.com/zalando/planb-tokeninfo/handlers/jwks"
	"github.com/zalando/planb-tokeninfo/handlers/metrics"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo/errorall"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo/jwt"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo/proxy"
	"github.com/zalando/planb-tokeninfo/ht"
	"github.com/zalando/planb-tokeninfo/keyloader/openid"
	"github.com/zalando/planb-tokeninfo/options"
	"github.com/zalando/planb-tokeninfo/revoke"
)

var version string

func setupMetrics(s *options.Settings) {
	gometrics.RegisterRuntimeMemStats(gometrics.DefaultRegistry)
	go gometrics.CaptureRuntimeMemStats(gometrics.DefaultRegistry, 60*time.Second)
	http.Handle("/metrics", metrics.Default)
	go func() {
		log.Printf("ERROR: %s", http.ListenAndServe(s.MetricsListenAddress, nil))
	}()
}

func Run(settings *options.Settings) {
	log.Printf("Started server (%s) at %v, /metrics endpoint at %v\n",
		version, settings.ListenAddress, settings.MetricsListenAddress)
	ht.UserAgent = fmt.Sprintf("%v/%s", os.Args[0], version)
	setupMetrics(settings)

	var ph http.Handler
	if settings.UpstreamTokenInfoURL != nil {
		ph = tokeninfoproxy.NewTokenInfoProxyHandler(settings.UpstreamTokenInfoURL, settings.UpstreamCacheMaxSize, settings.UpstreamCacheTTL, settings.UpstreamTimeout)
	} else {
		ph = errorall.NewErrorAllHandler()
	}
	kl := openid.NewCachingOpenIDProviderLoader(settings.OpenIDProviderConfigurationURL)
	crp := revoke.NewCachingRevokeProvider(settings.RevocationProviderUrl)
	jh := jwthandler.New(kl, crp)

	mux := http.NewServeMux()
	mux.Handle("/health", healthcheck.NewHandler(kl, version))
	mux.Handle("/oauth2/tokeninfo", tokeninfo.NewHandler(ph, jh))
	mux.Handle("/oauth2/connect/keys", jwks.NewHandler(kl))
	log.Fatal(http.ListenAndServe(settings.ListenAddress, mux))
}
