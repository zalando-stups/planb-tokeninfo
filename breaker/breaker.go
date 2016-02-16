package breaker

import (
	"github.com/afex/hystrix-go/hystrix"
	"net/http"
)

func Do(name string, url string) (resp *http.Response, err error) {
	return DoWithFallback(name, url, nil)
}

func DoWithFallback(name string, url string, f func(error) error) (resp *http.Response, err error) {
	err = hystrix.Do(name, func() error {
		resp, err = http.Get(url)
		return err
	}, f)
	return
}
