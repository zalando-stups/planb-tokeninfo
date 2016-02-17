package keys

import (
	"encoding/json"
	"fmt"
	"github.com/coreos/dex/pkg/log"
	"github.com/zalando/planb-tokeninfo/breaker"
	"github.com/zalando/planb-tokeninfo/options"
	"io/ioutil"
	"net/url"
	"reflect"
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

// Example: https://www.googleapis.com/oauth2/v3/certs
func (kl *cachingOpenIdProviderLoader) refreshKeys() {
	log.Info("Refreshing keys..")

	log.Info("Loading configuration..")
	c, err := kl.loadConfiguration()
	if err != nil {
		log.Errorf("Failed to get configuration from %q. %s", kl.url, err)
		return
	}

	log.Info("Configuration loaded successfully, loading JWKS..")
	resp, err := breaker.Do("loadKeys", c.JwksUri)
	if err != nil {
		log.Error("Failed to get JWKS from ", c.JwksUri)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Failed to read JWKS response from %q: %v", c.JwksUri, err)
	}

	log.Info("JWKS loaded successfully, parsing JWKS..")
	jwks := new(jsonWebKeySet)
	if err = json.Unmarshal(body, jwks); err != nil {
		log.Error("Failed to parse JWKS: ", err)
		return
	}

	for _, k := range jwks.Keys {
		var old = kl.keyCache.Get(k.KeyId)
		kl.keyCache.Set(k.KeyId, k.Key)
		if old == nil {
			log.Infof("Received new public key '%s'", k.KeyId)
		} else if !reflect.DeepEqual(old, k.Key) {
			log.Warningf("Received new public key for existing key '%s'", k.KeyId)
		}
	}

	log.Info("Refresh done..")
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
