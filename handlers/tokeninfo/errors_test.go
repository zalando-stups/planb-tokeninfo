package tokeninfo

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestErrorEncoding(t *testing.T) {
	w := httptest.NewRecorder()
	Error(w, TokenInfoError{Error: "foo", ErrorDescription: "bar", statusCode: http.StatusBadRequest})

	if w.Code != http.StatusBadRequest {
		t.Errorf("Wrong status code. Wanted %d, got %d", http.StatusBadRequest, w.Code)
	}

	want := `{"error":"foo","error_description":"bar"}` + "\n"
	if w.Body.String() != want {
		t.Errorf("Wrong body. Wanted %q, got %q", want, w.Body.String())
	}
}
