package jwthandler

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type mockKeyLoader int

var (
	testRSAToken   string
	testECDSAToken string

	testECDSAPKey *ecdsa.PublicKey
	testRSAPKey   *rsa.PublicKey
)

func (kl *mockKeyLoader) LoadKey(id string) (interface{}, error) {
	switch id {
	case "RS256":
		return testRSAPKey, nil
	case "ES256":
		return testECDSAPKey, nil
	default:
		return nil, ErrInvalidKeyId
	}
}

func init() {
	data, _ := ioutil.ReadFile("testdata/rs256.pub")
	block, _ := pem.Decode(data)
	pkey, _ := x509.ParsePKIXPublicKey(block.Bytes)
	testRSAPKey = pkey.(*rsa.PublicKey)

	data, _ = ioutil.ReadFile("testdata/es256.pub")
	block, _ = pem.Decode(data)
	pkey, _ = x509.ParsePKIXPublicKey(block.Bytes)
	testECDSAPKey = pkey.(*ecdsa.PublicKey)

	rsa, _ := ioutil.ReadFile("testdata/rsa.token")
	testRSAToken = string(rsa)

	ecdsa, _ := ioutil.ReadFile("testdata/ecdsa.token")
	testECDSAToken = string(ecdsa)
}

func TestHandler(t *testing.T) {
	kl := new(mockKeyLoader)
	h := NewJwtHandler(kl)

	for _, test := range []struct {
		token    string
		wantCode int
		wantBody string
	}{
		{"", http.StatusBadRequest, `{"error":"invalid_request","error_description":"Access Token not valid"}` + "\n"},
		{"foo", http.StatusUnauthorized, `{"error":"invalid_token","error_description":"Access Token not valid"}` + "\n"},
		{testRSAToken, http.StatusOK, testRSAToken},
		{testECDSAToken, http.StatusOK, testECDSAToken},
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

		if test.wantCode == http.StatusOK {
			var ti TokenInfo
			if err := json.NewDecoder(w.Body).Decode(&ti); err != nil {
				t.Error("Could not recover TokenInfo from response: ", err)
			}

			if ti.ExpiresIn <= 0 {
				t.Error("Recovered token info had an invalid expire time")
			}
		}
	}
}

func TestRoutingMatch(t *testing.T) {
	kl := new(mockKeyLoader)
	h := NewJwtHandler(kl)
	for _, test := range []struct {
		url  string
		want bool
	}{
		{"http://example.com/oauth2/tokeninfo", false},
		{"http://example.com/oauth2/tokeninfo?access_token", false},
		{"http://example.com/oauth2/tokeninfo?access_token=foo", false},
		{"http://example.com/oauth2/tokeninfo?access_token=foo.bar", false},
		{"http://example.com/oauth2/tokeninfo?access_token=header.claims.signature", true},
	} {
		req, _ := http.NewRequest("GET", test.url, nil)
		match := h.Match(req)
		if match != test.want {
			t.Errorf("Matching fail for URL %q. Wanted %t, got %t", test.url, test.want, match)
		}

	}
}

func TestHandlerCreation(t *testing.T) {
	kl := new(mockKeyLoader)
	h := NewJwtHandler(kl)
	jh, ok := h.(*jwtHandler)
	if !ok {
		t.Fatalf("Wrong type for the handler = %v", reflect.TypeOf(h))
	}

	if jh.keyLoader != kl {
		t.Error("Handler doesn't have the right key loader")
	}
}
