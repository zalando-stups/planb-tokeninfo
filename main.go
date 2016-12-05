package main

import (
	"github.com/zalando/planb-tokeninfo/options"
	"github.com/zalando/planb-tokeninfo/runner"
	"log"
)

func main() {
	if err := options.LoadFromEnvironment(); err != nil {
		log.Fatal(err)
	}
	runner.Run(options.AppSettings)
}
