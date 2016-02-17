package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	gometrics "github.com/rcrowley/go-metrics"
	"github.com/zalando/planb-tokeninfo/handlers/healthcheck"
	"github.com/zalando/planb-tokeninfo/handlers/metrics"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo/jwt"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo/proxy"
	"github.com/zalando/planb-tokeninfo/ht"
	"github.com/zalando/planb-tokeninfo/keys"
	"github.com/zalando/planb-tokeninfo/options"
)

var version string

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
	log.Printf("Started server (%s) at %v, /metrics endpoint at %v\n",
		version, options.ListenAddress, options.MetricsListenAddress)
	ht.UserAgent = fmt.Sprintf("%v/%s", os.Args[0], version)
	setupMetrics()

	ph := tokeninfoproxy.NewTokenInfoProxyHandler(options.UpstreamTokenInfoUrl)
	kl := keys.NewCachingOpenIdProviderLoader(options.OpenIdProviderConfigurationUrl)
	jh := jwthandler.NewJwtHandler(kl)

	mux := http.NewServeMux()
	mux.Handle("/health", healthcheck.Handler(fmt.Sprintf("OK\n%s", version)))
	mux.Handle("/oauth2/tokeninfo", tokeninfo.Handler(ph, jh))
	log.Fatal(http.ListenAndServe(options.ListenAddress, mux))
}
