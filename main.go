package main

import (
	"fmt"
	"github.com/coreos/dex/pkg/log"
	gometrics "github.com/rcrowley/go-metrics"
	"github.com/zalando/planb-tokeninfo/handlers/healthcheck"
	"github.com/zalando/planb-tokeninfo/handlers/metrics"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo/jwt"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo/proxy"
	"net/http"
	"os"
	"net/url"
)

const (
	defaultListenAddr        = ":9021"
	defaultMetricsListenAddr = ":9020"
)

var (
	Version string = "0.0.1"
)

func main() {
	log.Infof("Started server at %v.\n", defaultListenAddr)
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
	jh := jwthandler.DefaultJwtHandler()
	mux.Handle("/oauth2/tokeninfo", tokeninfo.Handler(ph, jh))
	log.Fatal(http.ListenAndServe(defaultListenAddr, mux))
}
