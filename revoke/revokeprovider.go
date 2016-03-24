package revoke

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/rcrowley/go-metrics"
	"github.com/zalando/planb-tokeninfo/breaker"
	"github.com/zalando/planb-tokeninfo/options"
)

// always refresh with additional tolerance to make sure we catch all revocations
// (server clocks might not be synchronized, Cassandra replication might be delayed)
const refreshToleranceSeconds = 60

var scheduleFunc = Schedule

type CachingRevokeProvider struct {
	url   string
	cache *Cache
}

func NewCachingRevokeProvider(u *url.URL) *CachingRevokeProvider {
	crp := &CachingRevokeProvider{url: u.String(), cache: NewCache()}
	scheduleFunc(options.AppSettings.RevocationProviderRefreshInterval, crp.RefreshRevocations)
	return crp
}

func (crp *CachingRevokeProvider) RefreshRevocations() {
	ts := crp.cache.GetLastTS()
	if ts == 0 {
		ts = int(time.Now().Add(-1 * options.AppSettings.RevocationCacheTTL).Unix())
	}
	ts = ts - refreshToleranceSeconds

	log.Printf("Checking for new revocations since %d...", ts)

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
		r := crp.cache.Get(REVOCATION_TYPE_FORCEREFRESH)
		if r == nil || (r != nil && r.(*Revocation).Timestamp != jr.Meta.RefreshTimestamp) {
			log.Printf("Force refreshing cache from %d...", jr.Meta.RefreshFrom)
			crp.cache.ForceRefresh(jr.Meta.RefreshFrom)
			rev := new(Revocation)
			d := make(map[string]interface{})
			rev.Type = REVOCATION_TYPE_FORCEREFRESH
			d["refresh_from"] = jr.Meta.RefreshFrom
			rev.Data = d
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

	if _, ok := j.Claims["iat"]; !ok {
		log.Println("JWT missing required field 'iat'")
		return false
	}
	iat := int(j.Claims["iat"].(float64))

	// check global revocation
	if r := crp.cache.Get(REVOCATION_TYPE_GLOBAL); r != nil {
		if val, ok := r.(*Revocation).Data["issued_before"]; ok && val.(int) > iat {
			countRevocations(REVOCATION_TYPE_GLOBAL)
			return true
		}
	}

	// check token revocation
	th := hashTokenClaim(j.Raw)
	if r := crp.cache.Get(th); r != nil {
		if val, ok := r.(*Revocation).Data["revoked_at"]; ok && val.(int) < iat {
			countRevocations(REVOCATION_TYPE_TOKEN)
			return true
		}
	}

	// check claim revocation
	// each cNames entry can have multiple claim names separated by a '|'
	// if multiple claim names, the values are appended with a '|' between and hashed
	cNames := crp.cache.GetClaimNames()
	for _, cName := range cNames {
		names := strings.Split(cName, "|")
		var vals string
		for _, n := range names {
			val, ok := j.Claims[n]
			if !ok {
				break
			}
			if vals == "" {
				vals = val.(string)
				continue
			}
			vals += "|" + val.(string)
		}
		ch := hashTokenClaim(vals)
		if r := crp.cache.Get(ch); r != nil {
			if v, ok := r.(*Revocation).Data["issued_before"]; ok && v.(int) > iat {
				countRevocations(REVOCATION_TYPE_CLAIM)
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
