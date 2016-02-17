package revoke

import (
	"github.com/zalando/planb-tokeninfo/options"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

type cachingRevokeProvider struct {
	url   string
	cache *Cache
}

func newCachingRevokeProvider(u url.URL) *cachingRevokeProvider {
	crp := &cachingRevokeProvider{url: u.String(), cache: NewCache()}
	schedule(options.RevocationProviderRefreshInterval, crp.refreshRevocations)
	return crp
}

// TODO: I don't like how I'm doing the force refresh here.
// if refreshTs is not an empty string, use that as the refresh time
func (crp *cachingRevokeProvider) refreshRevocations() {

	ts := ""

	// TODO need to get timestamp of last pull
	/*
		if crp.cache.timestamp != nil {
			c := <-crp.cache.timestamp
			ts = "?from=" + strconv.Itoa(c)
		}
	*/
	resp, err := http.Get(crp.url + ts)
	if err != nil {
		log.Println("Failed to get revocations. " + err.Error())
		return
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	jr := new(jsonRevoke)
	if err := jr.UnmarshallJSON(body); err != nil {
		log.Println("Failed to unmarshall revocation data. " + err.Error())
		return
	}

	for _, j := range jr.Revs {
		var r = new(Revocation)
		r.getRevocationFromJson(&j)
		crp.cache.Add(r)
	}

}
