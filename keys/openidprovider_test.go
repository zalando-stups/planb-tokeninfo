package keys

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestLoadKeys(t *testing.T) {
	var listener string

	handler := func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		if req.URL.Path == "/.well-known/openid-configuration" {
			w.Write([]byte(`{"issuer": "PlanB", "jwks_uri": "` + listener + `/oauth2/v3/certs"}`))
		} else {
			w.Write([]byte(`{
			  "keys": [
			    {
		"alg": "ES256",
		"crv": "P-256",
		"kid": "testkey",
		"kty": "EC",
		"use": "sign",
		"x":   "_5Z_cB5zhjVCt_GMfiC6sSBos0podt-YJicV6_GzDD0",
		"y":   "02LHDzZYup0SlbuqjNPBhr2X_LGamSgRidzKXsA0TFs"
			    }
			  ]
			}`))
		}
	}

	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	listener = fmt.Sprintf("http://%s", server.Listener.Addr())
	u, _ := url.Parse(listener + "/.well-known/openid-configuration")
	kl := &cachingOpenIdProviderLoader{url: u, keyCache: NewCache()}
	kl.refreshKeys()
	testkey := kl.keyCache.Get("testkey")

	if testkey == nil {
		t.Error("Failed to load key `testkey`")
	}

	k, ok := testkey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("Key is not a valid ECDSA PublicKey")
	}

	if k.X.String() != "115605682992956648477207773228188197675834354094591455680101846301827874884669" {
		t.Errorf("Wrong value in the X coordinate of the key %q", k.X.String())
	}

	if k.Y.String() != "95612535921063065667323916928898556799062466564160183670678964239934927686747" {
		t.Errorf("Wrong value in the Y coordinate of the key %q", k.Y.String())
	}
}
