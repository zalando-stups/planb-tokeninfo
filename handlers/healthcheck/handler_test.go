package healthcheck

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandler(t *testing.T) {
	for _, test := range []struct {
		h        http.Handler
		wantCode int
		wantResp string
	}{
		{Default, http.StatusOK, string(Default)},
		{Handler("PlanB"), http.StatusOK, "PlanB"},
	} {
		rw := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "http://example.com", nil)
		test.h.ServeHTTP(rw, r)

		if rw.Code != test.wantCode {
			t.Errorf("Handler returned wrong status code. Expected %d but got %d", test.wantCode, rw.Code)
		}

		if rw.Body.String() != test.wantResp {
			t.Errorf("Handler returned wrong response. Expected '%s' but got '%s", test.wantResp, rw.Body.String())
		}

	}

}
