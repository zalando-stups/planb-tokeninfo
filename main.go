package main

import (
	"fmt"
	"gitbub.com/zalando/planb-tokeninfo/revoke"
	gometrics "github.com/rcrowley/go-metrics"
	"github.com/zalando/planb-tokeninfo/handlers/healthcheck"
	"github.com/zalando/planb-tokeninfo/handlers/metrics"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo/jwt"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo/proxy"
	"github.com/zalando/planb-tokeninfo/keys"
	"github.com/zalando/planb-tokeninfo/options"
	"log"
	"net/http"
	"time"
)

var version string = "0.0.1"

func init() {
	options.LoadFromEnvironment()
}

func setupMetrics() {
	gometrics.RegisterRuntimeMemStats(gometrics.DefaultRegistry)
	go gometrics.CaptureRuntimeMemStats(gometrics.DefaultRegistry, 60*time.Second)
	http.Handle("/metrics", metrics.Default)
	go http.ListenAndServe(options.MetricsListenAddress, nil)
}

func main() {
	log.Printf("Started server at %v, /metrics endpoint at %v\n",
		options.ListenAddress, options.MetricsListenAddress)

	setupMetrics()

	ph := tokeninfoproxy.NewTokenInfoProxyHandler(options.UpstreamTokenInfoUrl)
	kl := keys.NewCachingOpenIdProviderLoader(options.OpenIdProviderConfigurationUrl)
	jh := jwthandler.NewJwtHandler(kl)
	crp := revoke.newCachingRevokeProvider(options.RevocationProviderUrl)

	mux := http.NewServeMux()
	mux.Handle("/health", healthcheck.Handler(fmt.Sprintf("OK\n%s", version)))
	mux.Handle("/oauth2/tokeninfo", tokeninfo.Handler(ph, jh))
	log.Fatal(http.ListenAndServe(options.ListenAddress, mux))
}
