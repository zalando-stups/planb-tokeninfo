package errorall

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zalando/planb-tokeninfo/handlers/tokeninfo"
)

type testHandler struct {
}

func (h *testHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusInternalServerError)
}

func (h *testHandler) Match(r *http.Request) bool {
	return false
}

func TestInvalidRequest(t *testing.T) {
	h1 := &testHandler{}
	h := tokeninfo.NewHandler(NewErrorAllHandler(), h1)

	req := &http.Request{Header: make(http.Header)}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "invalid_request") {
		t.Errorf("expected invalid_request response, but got %q", w.Body.String())
	}
}

func TestInvalidToken(t *testing.T) {
	h1 := &testHandler{}
	h := tokeninfo.NewHandler(NewErrorAllHandler(), h1)

	req := &http.Request{Header: make(http.Header)}
	w := httptest.NewRecorder()
	req.Header.Set("Authorization", "Bearer 1234")
	h.ServeHTTP(w, req)
	if !strings.Contains(w.Body.String(), "invalid_token") {
		t.Errorf("expected invalid_token response, but got %q", w.Body.String())
	}
}
