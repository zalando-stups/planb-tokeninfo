package revoke

import (
	"github.com/dgrijalva/jwt-go"
	"testing"
)

/*
func TestHashTokenClaim(t *testing.T) {
	t.Errorf("Hash: %s", hashTokenClaim("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6InJyZWlzIiwiYWRtaW4iOnRydWV9.UlZhyvrY9e7tRU88l8sfRb37oWGiL2t4insnO9Nsn1c"))
	t.Errorf("Hash: %s", hashTokenClaim("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIiwibmFtZSI6ImhqYWNvYnMiLCJhZG1pbiI6dHJ1ZX0.juP59kVFwPKyUCDNYZA6r_9wrWkLu7zJPsIRrrIYpls"))
	t.Errorf("Hash: %s", hashTokenClaim("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIzIiwibmFtZSI6ImxtaW5laXJvIiwiYWRtaW4iOnRydWV9.q8aDgIeENBpSrUbndIFeLLF5oNXhEGoVngsE7ltqyR4"))
	t.Errorf("Hash: %s", hashTokenClaim("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0IiwibmFtZSI6InRzYXJub3dza2kiLCJhZG1pbiI6dHJ1ZX0.T3ISN9ChkaHmFvTc_5Gb_ldXaL-Ca6qzrmDVhtuZtEQ"))
	t.Errorf("Hash: %s", hashTokenClaim("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1IiwibmFtZSI6ImFoYXJ0bWFubiIsImFkbWluIjp0cnVlfQ.PEGx0YG9Kr3BMcl-331GiIhz14PmbU5CBBENVvrFI9k"))
	t.Errorf("Hash: %s", hashTokenClaim("3035729288"))
	t.Errorf("Hash: %s", hashTokenClaim("0123456710"))
	t.Errorf("Hash: %s", hashTokenClaim("011011100"))
	t.Errorf("Hash: %s", hashTokenClaim("0123456789"))
}
*/

func TestIsJWTRevoked(t *testing.T) {

	rawJwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6InJyZWlzIiwiYWRtaW4iOnRydWV9.UlZhyvrY9e7tRU88l8sfRb37oWGiL2t4insnO9Nsn1c"
	sub := "sub"
	subVal := "jeff@zalando"

	crp := &cachingRevokeProvider{url: "localhost", cache: NewCache()}

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
	tc["iat"] = "400000"
	jt := &jwt.Token{Raw: rawJwt, Claims: tc}

	if !crp.isJWTRevoked(jt) {
		t.Errorf("Token should be revoked. %#v", jt)
	}

	tc["iat"] = "250000"
	jt = &jwt.Token{Raw: rawJwt, Claims: tc}
	if crp.isJWTRevoked(jt) {
		t.Errorf("Token should not be revoked. %#v", jt)
	}
	crp.cache.Delete(hashTokenClaim(rawJwt))

	// Revoke a claim
	tc["iat"] = "150000"
	jt = &jwt.Token{Claims: tc}
	if !crp.isJWTRevoked(jt) {
		t.Errorf("Claim should be revoked. %#v", jt)
	}

	tc["iat"] = "250000"
	jt = &jwt.Token{Claims: tc}
	if crp.isJWTRevoked(jt) {
		t.Errorf("Claim should not be revoked. %#v", jt)
	}
	crp.cache.Delete(sub + hashTokenClaim(subVal))

	// Global revocation
	tc["iat"] = "50000"
	jt = &jwt.Token{Raw: rawJwt, Claims: tc}
	if !crp.isJWTRevoked(jt) {
		t.Errorf("Token should be revoked (GLOBAL). %#v", jt)
	}

	tc["iat"] = "150000"
	jt = &jwt.Token{Raw: rawJwt, Claims: tc}
	if crp.isJWTRevoked(jt) {
		t.Errorf("Token should not be revoked (GLOBAL). %#v", jt)
	}

}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
