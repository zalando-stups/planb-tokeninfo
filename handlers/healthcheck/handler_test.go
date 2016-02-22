package healthcheck

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type mockLoaderWithKeys int

func (m *mockLoaderWithKeys) LoadKey(_ string) (interface{}, error) { return "dummy", nil }
func (m *mockLoaderWithKeys) Keys() map[string]interface{} {
	return map[string]interface{}{"dummy": "things"}
}

type mockLoaderWithoutKeys int

func (m *mockLoaderWithoutKeys) LoadKey(_ string) (interface{}, error) { return "dummy", nil }
func (m *mockLoaderWithoutKeys) Keys() map[string]interface{}          { return map[string]interface{}{} }

func TestHandler(t *testing.T) {
	for _, test := range []struct {
		h        http.Handler
		wantCode int
		wantResp string
	}{
		{NewHandler(new(mockLoaderWithKeys), "v1"), http.StatusOK, "OK\nv1"},
		{NewHandler(new(mockLoaderWithKeys), "v2"), http.StatusOK, "OK\nv2"},
		{NewHandler(new(mockLoaderWithoutKeys), "x"), http.StatusServiceUnavailable, "No keys available\nx"},
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
