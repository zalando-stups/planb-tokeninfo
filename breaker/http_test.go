package breaker

import (
	"fmt"
	"github.com/afex/hystrix-go/hystrix"
	"github.com/rcrowley/go-metrics"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCircuitBreaker(t *testing.T) {
	metrics.UseNilMetrics = true
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "bar")
	}

	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	url := fmt.Sprintf("http://%s", server.Listener.Addr())
	resp, err := Get("foo", url)

	if err != nil {
		t.Error("Failed to send request: ", err)
	}

	defer resp.Body.Close()
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Error("Failed to read body from response: ", err)
	}

	if string(buf) != "bar" {
		t.Error("Received wrong response body. Wanted `bar`, got %q", string(buf))
	}

	metric := metrics.Get("planb.breaker.foo")
	if metric == nil {
		t.Error("Request failed to produce metrics")
	}

	if _, ok := metric.(metrics.Timer); !ok {
		t.Error("Metric produced is not a timer")
	}
}

func TestCircuitBreakerFailures(t *testing.T) {
	metrics.UseNilMetrics = true
	var probe = 1
	_, err := GetWithFallback("fallback", "invalid-url", func(e error) error {
		if e == nil {
			t.Error("Circuit should call the fallack with the previous error")
		}
		probe = 42
		return nil
	})

	if err != nil {
		t.Error("Circuit should've have succeeded with the fallback")
	}

	if probe != 42 {
		t.Error("Expected the circuit breaker to use the fallback")
	}

	// hystrix.DefaultVolumeThreshold == 20
	i := 0
	for i < 21 {
		Get("fail", "invalid-url")
		i++
	}

	_, err = Get("fail", "invalid-url")
	if err != hystrix.ErrCircuitOpen {
		t.Error("Error is not circuit open: ", err)
	}
}
