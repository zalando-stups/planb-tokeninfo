package unknownhandler

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestHandler(t *testing.T) {
	h := New()

	for _, test := range []struct {
		token    string
		wantCode int
		wantBody string
	}{
		{"", http.StatusBadRequest, `{"error":"invalid_token","error_description":"Access Token not valid"}` + "\n"},
		{"foo", http.StatusBadRequest, `{"error":"invalid_token","error_description":"Access Token not valid"}` + "\n"},
	} {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "http://example.com/oauth2/tokeninfo?access_token="+test.token, nil)
		h.ServeHTTP(w, req)

		if test.wantCode != w.Code {
			t.Errorf("Wrong status code. Wanted %d, got %d", test.wantCode, w.Code)
		}

		if !strings.Contains(w.Body.String(), test.wantBody) {
			t.Errorf("Wrong response body. Wanted %q, got %q", test.wantBody, w.Body.String())
		}
	}
}

func TestHandlerCreation(t *testing.T) {
	h := New()
	_, ok := h.(*unknownHandler)
	if !ok {
		t.Fatalf("Wrong type for the handler = %v", reflect.TypeOf(h))
	}
}
