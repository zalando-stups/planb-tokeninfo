package main

import (
	"fmt"
	gometrics "github.com/rcrowley/go-metrics"
	"github.com/zalando/planb-agent/handlers/healthcheck"
	"github.com/zalando/planb-agent/handlers/metrics"
	"github.com/zalando/planb-agent/handlers/tokeninfo"
	"log"
	"net/http"
)

const (
	defaultListenAddr = ":9021"
)

var (
	Version string = "0.0.1"
)

func main() {
	fmt.Printf("Started server at %v.\n", defaultListenAddr)
	reg := gometrics.NewRegistry()
	mux := http.NewServeMux()
	mux.Handle("/health", healthcheck.DefaultHandler())
	mux.Handle("/metrics", metrics.NewHandler(reg))
	mux.Handle("/oauth2/tokeninfo", tokeninfo.DefaultTokenInfoHandler())
	log.Fatal(http.ListenAndServe(defaultListenAddr, mux))
}
