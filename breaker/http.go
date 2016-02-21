package breaker

import (
	"fmt"
	"net/http"
	"time"

	"github.com/afex/hystrix-go/hystrix"
	"github.com/rcrowley/go-metrics"
	"github.com/zalando/planb-tokeninfo/ht"
)

// Get will fetch the HTTP resource from url using a GET method, wrapped in a circuit breaker named name
func Get(name string, url string) (*http.Response, error) {
	return GetWithFallback(name, url, nil)
}

// GetWithFallback will fetch the HTTP resource from url using a GET method, wrapped in a circuit breaker named name.
// If the operation fails, the fallback function f is called with the previous error as an argument
func GetWithFallback(name string, url string, f func(error) error) (resp *http.Response, err error) {
	err = hystrix.Do(name, func() error {
		start := time.Now()
		var internalError error
		if resp, internalError = ht.Default.Get(url); internalError == nil {
			measureRequest(start, fmt.Sprintf("planb.breaker.%s", name))
		} else {
			registerFailure(name)
		}
		return internalError
	}, f)
	return
}

func measureRequest(start time.Time, key string) {
	if t, ok := metrics.DefaultRegistry.GetOrRegister(key, metrics.NewTimer).(metrics.Timer); ok {
		t.UpdateSince(start)
	}
}

func registerFailure(name string) {
	key := fmt.Sprintf("planb.breaker.%s.failure", name)
	if c, ok := metrics.DefaultRegistry.GetOrRegister(key, metrics.NewCounter).(metrics.Counter); ok {
		c.Inc(1)
	}
}
