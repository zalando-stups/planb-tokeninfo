package main

import (
	"log"

	"github.com/zalando/planb-tokeninfo/options"
	"github.com/zalando/planb-tokeninfo/runner"
)

func main() {
	if err := options.LoadFromEnvironment(); err != nil {
		log.Fatal(err)
	}
	runner.Run(options.AppSettings)
}
