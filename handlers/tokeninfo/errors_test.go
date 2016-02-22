package tokeninfo

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestErrorEncoding(t *testing.T) {
	for _, test := range []struct {
		given    Error
		want     string
		wantCode int
	}{
		{
			ErrInvalidRequest,
			`{"error":"invalid_request","error_description":"Access Token not valid"}` + "\n",
			http.StatusBadRequest,
		},
		{
			ErrInvalidToken,
			`{"error":"invalid_token","error_description":"Access Token not valid"}` + "\n",
			http.StatusUnauthorized,
		},
		{
			Error{Error: "foo", ErrorDescription: "bar", statusCode: http.StatusExpectationFailed},
			`{"error":"foo","error_description":"bar"}` + "\n",
			http.StatusExpectationFailed,
		},
	} {
		w := httptest.NewRecorder()
		test.given.Write(w)

		if w.Code != test.wantCode {
			t.Errorf("Wrong status code. Wanted %q, got %q", http.StatusText(test.wantCode), http.StatusText(w.Code))
		}

		if w.Body.String() != test.want {
			t.Errorf("Wrong body. Wanted %q, got %q", test.want, w.Body.String())
		}

	}
}
