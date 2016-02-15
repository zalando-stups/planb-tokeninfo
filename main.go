package main

import (
	"flag"
	"fmt"
	gometrics "github.com/rcrowley/go-metrics"
	"github.com/zalando/planb-tokeninfo/handlers/healthcheck"
	"github.com/zalando/planb-tokeninfo/handlers/metrics"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo/jwt"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo/proxy"
	"github.com/zalando/planb-tokeninfo/keys"
	"log"
	"net/http"
	"net/url"
	"os"
)

const (
	defaultListenAddr        = ":9021"
	defaultMetricsListenAddr = ":9020"
)

var (
	Version string = "0.0.1"
)

func init() {
	flag.Parse()
}

func main() {
	log.Println("Started server at %v.\n", defaultListenAddr)
	reg := gometrics.NewRegistry()
	mux := http.NewServeMux()
	mux.Handle("/health", healthcheck.Handler(fmt.Sprintf("OK\n%s", Version)))
	mux.Handle("/metrics", metrics.Handler(reg))

	upstream := os.Getenv("UPSTREAM_TOKENINFO_URL")
	url, err := url.Parse(upstream)
	if err != nil {
		log.Fatal(err)
	}

	ph := tokeninfoproxy.NewTokenInfoProxyHandler(url)
	if err != nil {
		log.Fatal(err)
	}

	u := os.Getenv("OPENID_PROVIDER_CONFIGURATION_URL")
	kl := keys.NewCachingOpenIdProviderLoader(u)
	jh := jwthandler.NewJwtHandler(kl)

	mux.Handle("/oauth2/tokeninfo", tokeninfo.Handler(ph, jh))
	log.Fatal(http.ListenAndServe(defaultListenAddr, mux))
}
