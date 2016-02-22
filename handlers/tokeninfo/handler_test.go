package tokeninfo

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

type testHandler struct {
	name  string
	value string
}

func (h *testHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s=%s", h.name, h.value)
}

func (h *testHandler) Match(r *http.Request) bool {
	v := r.Header.Get(h.name)
	return v == h.value
}

func TestRouting(t *testing.T) {
	def := &testHandler{name: "default", value: "def"}
	h1 := &testHandler{name: "x-header", value: "1"}
	h2 := &testHandler{name: "x-header", value: "2"}
	h3 := &testHandler{name: "x-test", value: "test"}

	h := NewHandler(def, h1, h2, h3)

	for _, test := range []struct {
		headerName  string
		headerValue string
		want        string
	}{
		{"foo", "bar", "default=def"},
		{"default", "x", "default=def"},
		{"x-header", "x", "default=def"},
		{"x-header", "1", "x-header=1"},
		{"x-header", "2", "x-header=2"},
		{"x-test", "y", "default=def"},
		{"x-test", "test", "x-test=test"},
	} {
		req := &http.Request{Header: make(http.Header)}
		w := httptest.NewRecorder()
		req.Header.Set(test.headerName, test.headerValue)
		h.ServeHTTP(w, req)
		if w.Body.String() != test.want {
			t.Errorf("Wrong output from routed request. Want %q, got %q", test.want, w.Body.String())
		}
	}
}

func TestAccessTokenFromRequest(t *testing.T) {
	for _, test := range []struct {
		r    http.Request
		want string
	}{
		{http.Request{Header: make(http.Header)}, ""},
		{http.Request{Header: http.Header{"Authorization": []string{"bleh"}}}, ""},
		{http.Request{Header: http.Header{"Authorization": []string{"bearer t1"}}}, "t1"},
		{http.Request{Header: http.Header{"Authorization": []string{"Bearer t2"}}}, "t2"},
		{http.Request{Header: http.Header{"Authorization": []string{"BeArEr t3"}}}, "t3"},
		{http.Request{Header: http.Header{"Authorization": []string{"BEARER t4"}}}, "t4"},
		{http.Request{Header: make(http.Header), Form: map[string][]string{"access_token": {"bar"}}}, "bar"},
	} {
		at := AccessTokenFromRequest(&test.r)
		if test.want != at {
			t.Errorf("Unexpected access token from request. Wanted %q, got %q", test.want, at)
		}
	}
}
