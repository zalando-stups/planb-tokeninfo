package main

import (
	"fmt"
	"github.com/coreos/dex/pkg/log"
	gometrics "github.com/rcrowley/go-metrics"
	"github.com/zalando/planb-tokeninfo/handlers/healthcheck"
	"github.com/zalando/planb-tokeninfo/handlers/metrics"
	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo"
	"net/http"
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
	mux.Handle("/oauth2/tokeninfo", tokeninfo.DefaultTokenRouterHandler())
	log.Fatal(http.ListenAndServe(defaultListenAddr, mux))
}
