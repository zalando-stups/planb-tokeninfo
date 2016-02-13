package tokeninfoproxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"net/url"
)

const testTokenInfo = `{"access_token": "xxx","cn": "John Doe","expires_in": 42,"grant_type": "password","realm":"/services","scope":["uid","cn"],"token_type":"Bearer","uid":"jdoe"}` + "\n"

func TestProxy(t *testing.T) {
	var upstream string

	handler := func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(testTokenInfo))
	}

	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	upstream = fmt.Sprintf("http://%s", server.Listener.Addr())
	url,_ := url.Parse(upstream)
	h := NewTokenInfoProxyHandler(url)
	invalid := `{"error":"invalid_request","error_description":"Access Token not valid"}` + "\n"
	for _, it := range []struct {
		query    string
		wantCode int
		wantBody string
	}{
		{"/oauth2/tokeninfo", http.StatusBadRequest, invalid},
		{"/oauth2/tokeninfo?access_token", http.StatusBadRequest, invalid},
		{"/oauth2/tokeninfo?access_token=foo", http.StatusOK, testTokenInfo},
	} {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "http://example.com" + it.query, nil)
		h.ServeHTTP(w, r)

		if w.Code != it.wantCode {
			t.Errorf("Wrong status code. Wanted %d, got %d", it.wantCode, w.Code)
		}

		if w.Body.String() != it.wantBody {
			t.Errorf("Wrong response body. Wanted %q, got %s", it.wantBody, w.Body.String())
		}
	}
}