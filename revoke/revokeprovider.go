package revoke

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/rcrowley/go-metrics"
	"github.com/zalando/planb-tokeninfo/options"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type CachingRevokeProvider struct {
	url   string
	cache *Cache
}

func NewCachingRevokeProvider(u *url.URL) *CachingRevokeProvider {
	crp := &CachingRevokeProvider{url: u.String(), cache: NewCache()}
	Schedule(options.AppSettings.RevocationProviderRefreshInterval, crp.RefreshRevocations)
	return crp
}

func (crp *CachingRevokeProvider) RefreshRevocations() {
	log.Println("refreshing revocations")

	ts := crp.cache.GetLastTS()
	if ts == 0 {
		ts = int(time.Now().Add(-1 * options.AppSettings.RevocationCacheTTL).Unix())
	}

	log.Println("Checking revocations from: %d", ts)

	resp, err := http.Get(crp.url + "?from=" + strconv.Itoa(ts))
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

	if jr.Meta.RefreshTimestamp != 0 {
		r := crp.cache.Get("FORCEREFRESH")
		if r != nil && r.(*Revocation).Timestamp != jr.Meta.RefreshTimestamp {
			crp.cache.ForceRefresh(jr.Meta.RefreshFrom)
			rev := new(Revocation)
			rev.Type = "FORCEREFRESH"
			rev.Data["refresh_from"] = jr.Meta.RefreshFrom
			rev.Timestamp = jr.Meta.RefreshTimestamp
			crp.cache.Add(rev)
		}

	}

	log.Printf("Number of new revocations: %d", len(jr.Revs))

	for _, j := range jr.Revs {
		var r = new(Revocation)
		r.getRevocationFromJson(&j)
		if r.Type != "" {
			crp.cache.Add(r)
		}
	}

	crp.cache.Expire()

}

func (crp *CachingRevokeProvider) IsJWTRevoked(j *jwt.Token) bool {

	iat := int(j.Claims["iat"].(float64))

	// check global revocation
	if r := crp.cache.Get("GLOBAL"); r != nil && r.(*Revocation).Data["issued_before"].(int) > iat {
		countRevocations("GLOBAL")
		return true
	}

	// check token revocation
	th := hashTokenClaim(j.Raw)
	if r := crp.cache.Get(th); r != nil && r.(*Revocation).Data["revoked_at"].(int) < iat {
		countRevocations("TOKEN")
		return true
	}

	// check claim revocation
	cn := crp.cache.GetClaimNames()
	if len(cn) == 0 {
		return false
	}
	for _, n := range cn {
		ch := n + hashTokenClaim(j.Claims[n].(string))
		if r := crp.cache.Get(ch); r != nil && r.(*Revocation).Data["issued_before"].(int) > iat {
			countRevocations("CLAIM")
			return true
		}
	}

	return false
}

func hashTokenClaim(h string) string {

	if h == "" {
		return ""
	}

	salt := options.AppSettings.HashingSalt
	buf := []byte(salt + h)
	hash := sha256.New()
	hash.Write(buf)
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))

}

func countRevocations(r string) {
	rev := fmt.Sprintf("planb.tokeninfo.revocation.%s", r)
	if c, ok := metrics.DefaultRegistry.GetOrRegister(rev, metrics.NewCounter).(metrics.Counter); ok {
		c.Inc(1)
	}
}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
