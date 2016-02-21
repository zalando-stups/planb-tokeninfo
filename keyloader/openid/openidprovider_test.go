package openid

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/zalando/planb-tokeninfo/caching"
	"github.com/zalando/planb-tokeninfo/keyloader"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func init() {
	scheduleFunc = noOpScheduler
}

func noOpScheduler(_ time.Duration, _ keyloader.JobFunc) {}

func TestLoadConfigurationFailure(t *testing.T) {
	kc := caching.NewCache()
	kc.Set("oldkey", "stuff")
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}

	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	listener := fmt.Sprintf("http://%s", server.Listener.Addr())
	kl := &cachingOpenIDProviderLoader{url: listener, keyCache: kc}
	kl.refreshKeys()

	if kc.Get("oldkey") == nil {
		t.Error("`oldkey` should still be in cache")
	}
}

func TestLoadJwksUriFailure(t *testing.T) {
	var listener string

	kc := caching.NewCache()
	kc.Set("oldkey", "stuff")
	handler := func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/.well-known/openid-configuration" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"issuer": "PlanB", "jwks_uri": "` + listener + `/oauth2/v3/certs"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}

	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	listener = fmt.Sprintf("http://%s", server.Listener.Addr())
	kl := &cachingOpenIDProviderLoader{url: listener + "/.well-known/openid-configuration", keyCache: kc}
	kl.refreshKeys()

	if kc.Get("oldkey") == nil {
		t.Error("`oldkey` should still be in cache")
	}
}

func TestLoadKeys(t *testing.T) {
	var listener string

	handler := func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		if req.URL.Path == "/.well-known/openid-configuration" {
			fmt.Fprintf(w, `{"issuer": "PlanB", "jwks_uri": "%s/oauth2/v3/certs"}`, listener)
		} else {
			fmt.Fprintf(w, `{
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
			}`)
		}
	}

	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	listener = fmt.Sprintf("http://%s", server.Listener.Addr())
	u, _ := url.Parse(listener + "/.well-known/openid-configuration")
	kl := NewCachingOpenIDProviderLoader(u)
	kl.(*cachingOpenIDProviderLoader).refreshKeys()
	testkey, err := kl.LoadKey("testkey")

	if testkey == nil || err != nil {
		t.Error("Failed to load key `testkey`: ", err)
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

	_, err = kl.LoadKey("missing-key")
	if err == nil {
		t.Error("Key 'missing-key' should not be retrieved from the key cache")
	}

	m := kl.Keys()
	if len(m) != 1 {
		t.Error("Wrong amount of keys")
	}

	if _, has := m["testkey"]; !has {
		t.Error("Key map doesn't contain 'testkey'")
	}
}

func TestRevokeKeys(t *testing.T) {
	var listener string

	kc := caching.NewCache()
	kc.Set("oldkey", []byte(`stuff`))
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		if req.URL.Path == "/.well-known/openid-configuration" {
			fmt.Fprintf(w, `{"issuer": "PlanB", "jwks_uri": "%s/oauth2/v3/certs"}`, listener)
		} else {
			fmt.Fprintf(w, `{
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
			}`)
		}
	}

	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	listener = fmt.Sprintf("http://%s", server.Listener.Addr())
	kl := &cachingOpenIDProviderLoader{url: listener + "/.well-known/openid-configuration", keyCache: kc}
	kl.refreshKeys()
	testkey := kl.keyCache.Get("testkey")

	if testkey == nil {
		t.Error("Failed to load key `testkey`")
	}

	oldkey := kl.keyCache.Get("oldkey")
	if oldkey != nil {
		t.Error("Failed to revoke key `oldkey`")
	}
}

func TestIgnoreEmptyKeys(t *testing.T) {
	var listener string

	kc := caching.NewCache()
	kc.Set("oldkey", []byte(`stuff`))
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		if req.URL.Path == "/.well-known/openid-configuration" {
			fmt.Fprintf(w, `{"issuer": "PlanB", "jwks_uri": "%s/oauth2/v3/certs"}`, listener)
		} else {
			w.Write([]byte(`{}`))
		}
	}

	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	listener = fmt.Sprintf("http://%s", server.Listener.Addr())
	kl := &cachingOpenIDProviderLoader{url: listener + "/.well-known/openid-configuration", keyCache: kc}
	kl.refreshKeys()

	oldkey := kl.keyCache.Get("oldkey")
	if oldkey == nil {
		t.Error("`oldkey` should not have been revoked")
	}
}

func TestInvalidJwksUri(t *testing.T) {
	handler := func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"issuer": "PlanB", "jwks_uri": "invalid-url"}`)
	}

	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	listener := fmt.Sprintf("http://%s/.well-known/openid-configuration", server.Listener.Addr())
	kc := caching.NewCache()
	kl := &cachingOpenIDProviderLoader{url: listener, keyCache: kc}
	kl.refreshKeys()

	m := kl.Keys()
	if len(m) != 0 {
		t.Error("Key amount should be 0")
	}
}
