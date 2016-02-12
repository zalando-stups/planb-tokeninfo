package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/coreos/dex/pkg/log"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
)

// http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
// https://planb-provider.example.org/.well-known/openid-configuration
type cachingOpenIdProviderLoader struct {
	url      string
	keyCache *Cache
}

const OPENID_PROVIDER_CONFIGURATION_URL = "OPENID_PROVIDER_CONFIGURATION_URL"

func newCachingOpenIdProviderLoader() KeyLoader {
	u := os.Getenv(OPENID_PROVIDER_CONFIGURATION_URL)
	if u == "" {
		log.Fatal("Missing OPENID_PROVIDER_CONFIGURATION_URL environment variable")
	}
	kl := &cachingOpenIdProviderLoader{url: u, keyCache: NewCache()}
	// TODO: schedule background refresh of keys
	kl.refreshKeys()
	return kl
}

func (kl *cachingOpenIdProviderLoader) LoadKey(id string) (interface{}, error) {
	var key = kl.keyCache.Get(id)
	if key == nil {
		return key, fmt.Errorf("Key '%s' not found", id)
	}
	return key, nil
}

func buildKey(k map[string]interface{}) (interface{}, error) {
	if k["alg"].(string) != "ES256" {
		return nil, fmt.Errorf("Unsupported algorithm '%s'", k["alg"].(string))
	}

	xbuf, err := base64.RawURLEncoding.DecodeString(k["x"].(string))
	if err != nil {
		return nil, fmt.Errorf("Invalid ECDSA coordinate X")
	}
	ybuf, err := base64.RawURLEncoding.DecodeString(k["y"].(string))
	if err != nil {
		return nil, fmt.Errorf("Invalid ECDSA coordinate Y")
	}

	x := new(big.Int).SetBytes(xbuf)
	y := new(big.Int).SetBytes(ybuf)

	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// Example: https://www.googleapis.com/oauth2/v3/certs
func (kl *cachingOpenIdProviderLoader) refreshKeys() {
	log.Info("Refreshing keys ...")

	c, err := kl.loadConfiguration()
	if err != nil {
		log.Error("Failed to get configuration from ", kl.url)
		return
	}

	resp, err := http.Get(c.JwksUri)
	if err != nil {
		log.Error("Failed to get JWKS from ", c.JwksUri)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	jwks := new(jsonWebKeySet)
	if err = json.Unmarshal(body, jwks); err != nil {
		log.Error("Failed to parse JWKS: ", err)
		return
	}

	for _, km := range jwks.Keys {
		if kid, has := km["kid"]; has {
			if id, ok := kid.(string); ok {
				k, err := buildKey(km)
				if err == nil {
					kl.keyCache.Set(id, k)
				} else {
					log.Errorf("Failed to build key `%s`: %v", id, err)
				}
			}
		}
	}
}

func (kl *cachingOpenIdProviderLoader) loadConfiguration() (*configuration, error) {
	resp, err := http.Get(kl.url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	config := new(configuration)
	if err = json.Unmarshal(body, config); err != nil {
		return nil, err
	}

	return config, nil
}
