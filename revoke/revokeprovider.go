package revoke

import (
	"io.ioutil"
	"net/nttp"
	"os"
	"strconv"
	"time"
)

type cachingRevokeProvider struct {
	url   string
	cache *Cache
}

// TODO: move to config? Is one minute proper? Should it be longer?
const defaultRefreshInterval = 60 * time.Second

const REVOCATION_PROVIDER_URL = "REVOCATION_PROVIDER_URL"

func newCachingRevokeProvider() *cachingRevokeProvider {
	u := os.Getenv(REVOCATION_PROVIDER_URL)
	crp := &cachingRevokeProvider{url: u, revockeCache: NewCache()}
	schedule(defaultRefreshInterval, crp.refreshRevocations)
	return crp
}

// TODO: I don't like how I'm doing the force refresh here.
// if refreshTs is not an empty string, use that as the refresh time
func (crp *cachingRevokeProvider) refreshRevocations(refreshTs string) {
	log.Info("Refreshing revocations. . .")

	ts := ""

	var forceRefresh bool
	// Note: we'll never get a force refresh on our first pull
	if refreshTs != "" {
		forceRefresh = true
		ts = "?from=" + refreshTs
		// TODO: do I need to remove all cache entries >= force refresh time?
	}

	// TODO refactor force refresh since what's below isn't going to work.
	if !forceRefresh {
		if crp.cache.timestamp != nil {
			c := <-crp.cache.timestamp
			ts = "?from=" + strconv.Itoa(c)
		}
	}

	resp, err := http.Get(crp.url + ts)
	if err != nil {
		log.Errorf("Failed to get revocations. " + err.Error())
		return
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	jr := new(jsonRevoke)
	if err := jr.UnmarshallJSON(body, forceRefresh); err != nil {
		log.Errorf("Failed to unmarshall revocation data. " + err.Error())
		return
	}

	var r []Revocation
	r.getRevocationFromJson(jr.Revocation)

	for rev := range r {
		rev.cache.Add(&rev)
	}

}
