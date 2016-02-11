package main

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
)

const (
	testToken = "eyJraWQiOiJ0ZXN0a2V5IiwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJQbGFuQiIsImV4cCI6MTQ1NTI0MjAzNywianRpIjoibXg3OTNtSWo3NGZQdWZrdVJ1c0U3dyIsImlhdCI6MTQ1NTIxMzIzNywic3ViIjoiZm9vIiwic2NvcGVzIjpbInVpZCJdLCJ1aWQiOiJmb28ifQ.viaQAWJS-8qqsJmUtkVs5B6eWIitN-sQqG0omfGxP-KO2qhTRAP-L0BaEyqnYByvuuVywo_v7ZbAySh7gkWk7w"
)

var (
	testKey = map[string]interface{}{
		"kty": "EC",
		"kid": "testkey",
		"use": "sign",
		"alg": "ES256",
		"x":   "aOTsn0HvWGfr5SiafItYelU1EWoGauPKV_ILkAmitUc",
		"y":   "pcutCSbmupjY3qMrCk8CEZned9uzbb_Hpujt7xhAqp0",
		"crv": "P-256",
	}
)

func TestBuildKey(t *testing.T) {
	pk, err := buildKey(testKey)

	if err != nil {
		t.Fatalf("Failed to build key for '%v': %v", testKey, err)
	}

	k, ok := pk.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("Key is not a valid ECDSA PublicKey")
	}

	if k.X.String() != "47445010489142298586605931444386967702765662589492616290394320492726036116807" {
		t.Error("Wrong value in the X coordinate of the key")
	}

	if k.Y.String() != "74991484219243264317759347595016293862146328102512480217905741311042866162333" {
		t.Error("Wrong value in the Y coordinate of the key")
	}
}

func TestValidateToken(t *testing.T) {
	var listener string

	handler := func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		if req.URL.Path == "/.well-known/openid-configuration" {
			w.Write([]byte(`{"issuer": "PlanB", "jwks_uri": "` + listener + `/oauth2/v3/certs"}`))
		} else {
			w.Write([]byte(`{
			  "keys": [
			    {
			      "kty": "EC",
			      "kid": "testkey",
			      "use": "sign",
			      "alg": "ES256",
			      "x": "aOTsn0HvWGfr5SiafItYelU1EWoGauPKV_ILkAmitUc",
			      "y": "pcutCSbmupjY3qMrCk8CEZned9uzbb_Hpujt7xhAqp0",
			      "crv": "P-256"
			    }
			  ]
			}`))
		}
	}

	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	listener = fmt.Sprintf("http://%s", server.Listener.Addr())
	os.Setenv(OPENID_PROVIDER_CONFIGURATION_URL, listener+"/.well-known/openid-configuration")
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	url, _ := url.Parse("http://example.com/oauth2/tokeninfo?access_token=" + testToken)
	req.URL = url
	ti, err := validateToken(req)

	if err != nil {
		t.Fatalf("Failed to validate test token %v", err)
	}

	if ti.OpenId != testToken {
		t.Errorf("Invalid content")
	}

	spew.Dump(ti)
}
