package revoke

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/rcrowley/go-metrics"
	"github.com/zalando/planb-tokeninfo/breaker"
	"github.com/zalando/planb-tokeninfo/options"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// always refresh with additional tolerance to make sure we catch all revocations
// (server clocks might not be synchronized, Cassandra replication might be delayed)
const refreshToleranceSeconds = 60

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
	ts := crp.cache.GetLastTS()
	if ts == 0 {
		ts = int(time.Now().Add(-1 * options.AppSettings.RevocationCacheTTL).Unix())
	}
	ts = ts - refreshToleranceSeconds

	log.Printf("Checking for new revocations since %d..", ts)

	resp, err := breaker.Get("refreshRevocations", crp.url+"?from="+strconv.Itoa(ts))
	if err != nil {
		log.Println("Failed to get revocations. " + err.Error())
		return
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Failed to get revocations. Server returned status %s.", resp.Status)
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

	if len(jr.Revs) > 0 {
		log.Printf("Received %d new revocations", len(jr.Revs))
	}

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
		val, ok := j.Claims[n]
		// claim might not be present in this JWT!
		if ok {
			ch := n + hashTokenClaim(val.(string))
			if r := crp.cache.Get(ch); r != nil && r.(*Revocation).Data["issued_before"].(int) > iat {
				countRevocations("CLAIM")
				return true
			}
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