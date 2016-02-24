package revoke

import (
//	"github.com/dgrijalva/jwt-go"
//	"testing"
)

/*
func TestHashTokenClaim(t *testing.T) {
	t.Errorf("Hash: %s", hashTokenClaim("Jeff"))
}
*/
/*
func TestIsJWTRevoked(t *testing.T) {

	access_token := "abcd-efgh-ijkl-mnop"
	subject := "theSub"
	scope := "theScope"

	crp := &cachingRevokeProvider{url: "localhost", cache: NewCache()}

	revData := make(map[string]interface{})
	revData["token_hash"] = hashTokenClaim(access_token)
	revData["revoked_at"] = "300000"
	rev := &Revocation{Type: "TOKEN", Data: revData, Timestamp: 300000}
	crp.cache.Add(rev)

	revData2 := make(map[string]interface{})
	revData2["value_hash"] = hashTokenClaim(subject + scope)
	revData2["issued_before"] = "200000"
	rev2 := &Revocation{Type: "CLAIM", Data: revData2, Timestamp: 200000}
	crp.cache.Add(rev2)

	revData3 := make(map[string]interface{})
	revData3["issued_before"] = "100000"
	rev3 := &Revocation{Type: "GLOBAL", Data: revData3, Timestamp: 100000}
	crp.cache.Add(rev3)

	// Revoking a token
	// TODO: this needs to change to use the whole token as a hash
	tc := make(map[string]interface{})
	tc["access_token"] = access_token
	tc["sub"] = subject
	tc["scope"] = scope
	tc["iat"] = "400000"
	jt := &jwt.Token{Claims: tc}

	if !crp.isJWTRevoked(jt) {
		t.Errorf("Token should be revoked. %#v", jt)
	}

	tc["iat"] = "250000"
	jt = &jwt.Token{Claims: tc}
	if crp.isJWTRevoked(jt) {
		t.Errorf("Token should not be revoked. %#v", jt)
	}
	crp.cache.Delete(hashTokenClaim(access_token))

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
	crp.cache.Delete(hashTokenClaim(subject + scope))

	// Global revocation
	tc["iat"] = "50000"
	jt = &jwt.Token{Claims: tc}
	if !crp.isJWTRevoked(jt) {
		t.Errorf("Token should be revoked (GLOBAL). %#v", jt)
	}

	tc["iat"] = "150000"
	jt = &jwt.Token{Claims: tc}
	if crp.isJWTRevoked(jt) {
		t.Errorf("Token should not be revoked (GLOBAL). %#v", jt)
	}

}
*/
// vim: ts=4 sw=4 noexpandtab nolist syn=go
