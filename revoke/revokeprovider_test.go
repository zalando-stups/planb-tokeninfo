package revoke

import (
	"github.com/dgrijalva/jwt-go"
	"testing"
)

func TestHashTokenClaimEmpty(t *testing.T) {
	h := hashTokenClaim("")
	if h != "" {
		t.Errorf("Hash should be an empty string. hash: %s", h)
	}
}
func TestHashTokenClaimValid(t *testing.T) {
	revHash := "j_FwkAS8Nw6eQgPybCH3jk8pgHOJ20AV7C9tK97P8Mg="
	h := hashTokenClaim("testingHashFunction")
	if h != revHash {
		t.Errorf("Hashes should match. expected: %s, actual: %s", revHash, h)
	}
}

func TestIsJWTRevoked(t *testing.T) {

	rawJwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6InJyZWlzIiwiYWRtaW4iOnRydWV9.UlZhyvrY9e7tRU88l8sfRb37oWGiL2t4insnO9Nsn1c"
	sub := "sub"
	subVal := "jeff@zalando"

	crp := &CachingRevokeProvider{url: "localhost", cache: NewCache()}

	// token
	revData := make(map[string]interface{})
	revData["token_hash"] = hashTokenClaim(rawJwt)
	revData["revoked_at"] = "300000"
	rev := &Revocation{Type: "TOKEN", Data: revData, Timestamp: 300000}
	crp.cache.Add(rev)

	// claim
	revData2 := make(map[string]interface{})
	revData2["value_hash"] = hashTokenClaim(subVal)
	revData2["issued_before"] = "200000"
	revData2["name"] = sub
	rev2 := &Revocation{Type: "CLAIM", Data: revData2, Timestamp: 200000}
	crp.cache.Add(rev2)

	// global
	revData3 := make(map[string]interface{})
	revData3["issued_before"] = "100000"
	rev3 := &Revocation{Type: "GLOBAL", Data: revData3, Timestamp: 100000}
	crp.cache.Add(rev3)

	// revoke a token
	tc := make(map[string]interface{})
	tc[sub] = subVal
	tc["iat"] = 400000.0
	jt := &jwt.Token{Raw: rawJwt, Claims: tc}

	if !crp.IsJWTRevoked(jt) {
		t.Errorf("Token should be revoked. %#v", jt)
	}

	tc["iat"] = 250000.0
	jt = &jwt.Token{Raw: rawJwt, Claims: tc}
	if crp.IsJWTRevoked(jt) {
		t.Errorf("Token should not be revoked. %#v", jt)
	}
	crp.cache.Delete(hashTokenClaim(rawJwt))

	// Revoke a claim
	tc["iat"] = 150000.0
	jt = &jwt.Token{Claims: tc}
	if !crp.IsJWTRevoked(jt) {
		t.Errorf("Claim should be revoked. %#v", jt)
	}

	tc["iat"] = 250000.0
	jt = &jwt.Token{Claims: tc}
	if crp.IsJWTRevoked(jt) {
		t.Errorf("Claim should not be revoked. %#v", jt)
	}
	crp.cache.Delete(sub + hashTokenClaim(subVal))

	// Global revocation
	tc["iat"] = 50000.0
	jt = &jwt.Token{Raw: rawJwt, Claims: tc}
	if !crp.IsJWTRevoked(jt) {
		t.Errorf("Token should be revoked (GLOBAL). %#v", jt)
	}

	tc["iat"] = 150000.0
	jt = &jwt.Token{Raw: rawJwt, Claims: tc}
	if crp.IsJWTRevoked(jt) {
		t.Errorf("Token should not be revoked (GLOBAL). %#v", jt)
	}

}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
