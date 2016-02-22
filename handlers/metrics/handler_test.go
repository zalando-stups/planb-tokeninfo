package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	gometrics "github.com/rcrowley/go-metrics"
)

const testJSONMetrics = `{"some.metric.key":{"15m.rate":0,"1m.rate":0,"5m.rate":0,"75%":0,"95%":0,"99%":0,"99.9%":0,"count":0,"max":0,"mean":0,"mean.rate":0,"median":0,"min":0,"stddev":0}}` + "\n"

func TestHandler(t *testing.T) {
	gometrics.UseNilMetrics = true
	gometrics.Register("some.metric.key", gometrics.NewTimer())

	rw := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	Default.ServeHTTP(rw, r)

	if rw.Code != http.StatusOK {
		t.Errorf("Metrics endpoint responded with wrong status code = %d", rw.Code)
	}

	if rw.Body.String() != testJSONMetrics {
		t.Errorf("Wrong metrics response. Want '%s', got '%s'", testJSONMetrics, rw.Body.String())
	}
}
