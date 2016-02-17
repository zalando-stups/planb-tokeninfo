package breaker

import (
	"fmt"
	"github.com/afex/hystrix-go/hystrix"
	"github.com/rcrowley/go-metrics"
	"net/http"
	"time"
)

func Do(name string, url string) (resp *http.Response, err error) {
	return DoWithFallback(name, url, nil)
}

func DoWithFallback(name string, url string, f func(error) error) (resp *http.Response, err error) {
	err = hystrix.Do(name, func() error {
		start := time.Now()
		if resp, err = Get(url); err == nil {
			measureRequest(start, fmt.Sprintf("planb.breaker.%s", name))
		}
		return err
	}, f)
	return
}

func measureRequest(start time.Time, key string) {
	t := metrics.DefaultRegistry.GetOrRegister(key, metrics.NewTimer).(metrics.Timer)
	t.UpdateSince(start)
}
