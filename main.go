package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"gitbub.com/zalando/planb-tokeninfo/revoke"
	gometrics "github.com/rcrowley/go-metrics"
	"github.com/zalando/planb-tokeninfo/handlers/healthcheck"
	"github.com/zalando/planb-tokeninfo/handlers/jwks"
	"github.com/zalando/planb-tokeninfo/handlers/metrics"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo/jwt"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo/proxy"
	"github.com/zalando/planb-tokeninfo/ht"
	"github.com/zalando/planb-tokeninfo/keyloader/openid"
	"github.com/zalando/planb-tokeninfo/options"
)

var version string

func setupMetrics(s *options.Settings) {
	gometrics.RegisterRuntimeMemStats(gometrics.DefaultRegistry)
	go gometrics.CaptureRuntimeMemStats(gometrics.DefaultRegistry, 60*time.Second)
	http.Handle("/metrics", metrics.Default)
	go http.ListenAndServe(s.MetricsListenAddress, nil)
}

func main() {
	if err := options.LoadFromEnvironment(); err != nil {
		log.Fatal(err)
	}
	settings := options.AppSettings

	log.Printf("Started server (%s) at %v, /metrics endpoint at %v\n",
		version, settings.ListenAddress, settings.MetricsListenAddress)
	ht.UserAgent = fmt.Sprintf("%v/%s", os.Args[0], version)
	setupMetrics(settings)

	ph := tokeninfoproxy.NewTokenInfoProxyHandler(options.UpstreamTokenInfoUrl)
	kl := keys.NewCachingOpenIdProviderLoader(options.OpenIdProviderConfigurationUrl)
	jh := jwthandler.NewJwtHandler(kl)
	crp := revoke.newCachingRevokeProvider(options.RevocationProviderUrl)

	mux := http.NewServeMux()
	mux.Handle("/health", healthcheck.NewHandler(kl, version))
	mux.Handle("/oauth2/tokeninfo", tokeninfo.NewHandler(ph, jh))
	mux.Handle("/oauth2/connect/keys", jwks.NewHandler(kl))
	log.Fatal(http.ListenAndServe(settings.ListenAddress, mux))
}
