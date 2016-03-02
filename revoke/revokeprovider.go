package revoke

import (
	"crypto/sha256"
	"encoding/base64"
	"github.com/dgrijalva/jwt-go"
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
	schedule(options.AppSettings.RevocationProviderRefreshInterval, crp.refreshRevocations)
	return crp
}

// TODO: force refresh
func (crp *CachingRevokeProvider) refreshRevocations() {
	log.Println("refreshing revocations")

	ts := crp.cache.GetLastTS()
	if ts == 0 {
		ts = int(time.Now().UnixNano()/1e6) - int(options.AppSettings.RevokeExpireLength)
	}

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

	log.Printf("Number of new revocations: %d", len(jr.Revs))

	for _, j := range jr.Revs {
		var r = new(Revocation)
		r.getRevocationFromJson(&j)
		if r.Type != "" {
			crp.cache.Add(r)
		}
	}

}

func (crp *CachingRevokeProvider) IsJWTRevoked(j *jwt.Token) bool {

	//iat, err := strconv.Atoi(j.Claims["iat"].(string))
	iat := int(j.Claims["iat"].(float64))
	//	if err != nil {
	//		log.Println("Error converting iat to int. " + err.Error())
	//		return false
	//	}

	// check global revocation
	if r := crp.cache.Get("GLOBAL"); r != nil && r.(*Revocation).Timestamp > iat {
		return true
	}

	// check token revocation
	th := hashTokenClaim(j.Raw)
	if r := crp.cache.Get(th); r != nil && r.(*Revocation).Timestamp < iat {
		return true
	}

	// check claim revocation
	cn := crp.cache.GetClaimNames()
	if len(cn) == 0 {
		return false
	}
	for _, n := range cn {
		ch := n + hashTokenClaim(j.Claims[n].(string))
		if r := crp.cache.Get(ch); r != nil && r.(*Revocation).Timestamp > iat {
			return true
		}
	}

	return false
}

func hashTokenClaim(h string) string {

	//	salt := options.HashingSalt
	salt := "seasaltisthebest"
	buf := []byte(salt + h)
	hash := sha256.New()
	hash.Write(buf)
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))

}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
