package keys

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"reflect"

	"github.com/zalando/planb-tokeninfo/breaker"
	"github.com/zalando/planb-tokeninfo/options"
)

// http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
// https://planb-provider.example.org/.well-known/openid-configuration
// https://accounts.google.com/.well-known/openid-configuration
type cachingOpenIdProviderLoader struct {
	url      string
	keyCache *Cache
}

func NewCachingOpenIdProviderLoader(u *url.URL) KeyLoader {
	kl := &cachingOpenIdProviderLoader{url: u.String(), keyCache: NewCache()}
	schedule(options.OpenIdProviderRefreshInterval, kl.refreshKeys)
	return kl
}

func (kl *cachingOpenIdProviderLoader) LoadKey(id string) (interface{}, error) {
	var key = kl.keyCache.Get(id)
	if key == nil {
		return key, fmt.Errorf("Key '%s' not found", id)
	}
	return key, nil
}

func (kl *cachingOpenIdProviderLoader) Keys() map[string]interface{} {
	return kl.keyCache.Snapshot()
}

// Example: https://www.googleapis.com/oauth2/v3/certs
func (kl *cachingOpenIdProviderLoader) refreshKeys() {
	log.Println("Refreshing keys..")

	log.Println("Loading configuration..")
	c, err := kl.loadConfiguration()
	if err != nil {
		log.Printf("Failed to get configuration from %q. %s\n", kl.url, err)
		return
	}

	log.Println("Configuration loaded successfully, loading JWKS..")
	resp, err := breaker.Do("loadKeys", c.JwksUri)
	if err != nil {
		log.Println("Failed to get JWKS from ", c.JwksUri)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Failed to read JWKS response body from %q: %v\n", c.JwksUri, err)
		return
	}

	log.Println("JWKS loaded successfully, parsing JWKS..")
	jwks := new(JsonWebKeySet)
	if err = json.Unmarshal(body, jwks); err != nil {
		log.Println("Failed to parse JWKS: ", err)
		return
	}

	for _, k := range jwks.Keys {
		var old = kl.keyCache.Get(k.KeyId)
		kl.keyCache.Set(k.KeyId, k.Key)
		if old == nil {
			log.Printf("Received new public key %q", k.KeyId)
		} else if !reflect.DeepEqual(old, k.Key) {
			log.Printf("Received new public key for existing key %q", k.KeyId)
		}
	}

	log.Println("Refresh done..")
}

func (kl *cachingOpenIdProviderLoader) loadConfiguration() (*configuration, error) {
	resp, err := breaker.Do("loadConfiguration", kl.url)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	config := new(configuration)
	err = json.Unmarshal(body, config)
	return config, err
}
