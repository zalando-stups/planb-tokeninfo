package revoke

import (
	"encoding/base64"
	"github.com/dgrijalva/jwt-go"
	"github.com/zalando/planb-tokeninfo/options"
	"golang.org/x/crypto/sha3"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type cachingRevokeProvider struct {
	url   string
	cache *Cache
}

func NewCachingRevokeProvider(u *url.URL) *cachingRevokeProvider {
	crp := &cachingRevokeProvider{url: u.String(), cache: NewCache()}
	schedule(options.RevocationProviderRefreshInterval, crp.refreshRevocations)
	return crp
}

// TODO: force refresh
func (crp *cachingRevokeProvider) refreshRevocations() {

	ts := crp.cache.GetLastTS()
	if ts == "" {
		ts = strconv.Itoa(int(time.Now().UnixNano()/1e6) - int(options.RevokeExpireLength))
	}

	resp, err := http.Get(crp.url + "?from=" + ts)
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
		if r.Type != "" {
			crp.cache.Add(r)
		}
	}

}

func (crp *cachingRevokeProvider) isJWTRevoked(j *jwt.Token) bool {

	iat, err := strconv.Atoi(j.Claims["iat"].(string))
	if err != nil {
		log.Println("Error converting iat to int. " + err.Error())
		return false
	}

	if r := crp.cache.Get("GLOBAL"); r != nil && r.Timestamp > iat {
		return true
	}

	th := hashTokenClaim(j.Raw)
	if r := crp.cache.Get(th); r != nil && r.Timestamp < iat {
		return true
	}

	// TODO: this isn't how this is going to work. . .
	// I think we're going to use uid for now.
	sub := j.Claims["sub"].(string)
	scope := j.Claims["scope"].(string)
	ch := hashTokenClaim(sub + scope)
	if r := crp.cache.Get(ch); r != nil && r.Timestamp > iat {
		return true
	}

	return false
}

func hashTokenClaim(h string) string {

	salt := options.HashingSalt
	buf := []byte(salt + h)
	hasher := sha3.New256()
	hasher.Write(buf)
	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))

}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
