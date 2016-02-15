package keys

import (
	"encoding/json"
	"fmt"
	"github.com/coreos/dex/pkg/log"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"time"
)

// http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
// https://planb-provider.example.org/.well-known/openid-configuration
type cachingOpenIdProviderLoader struct {
	url      string
	keyCache *Cache
}

const defaultRefreshInterval = 30 * time.Second

const OPENID_PROVIDER_CONFIGURATION_URL = "OPENID_PROVIDER_CONFIGURATION_URL"

func newCachingOpenIdProviderLoader() KeyLoader {
	u := os.Getenv(OPENID_PROVIDER_CONFIGURATION_URL)
	kl := &cachingOpenIdProviderLoader{url: u, keyCache: NewCache()}
	schedule(defaultRefreshInterval, kl.refreshKeys)
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

	for _, k := range jwks.Keys {
		var old = kl.keyCache.Get(k.KeyId)
		kl.keyCache.Set(k.KeyId, k.Key)
		if old == nil {
			log.Infof("Received new public key '%s'", k.KeyId)
		} else if !reflect.DeepEqual(old, k.Key) {
			log.Warningf("Received new public key for existing key '%s'", k.KeyId)
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
