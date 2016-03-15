package revoke

import (
	"github.com/dgrijalva/jwt-go"

	"testing"
)

/*
func init() {
	schedFunc = noSched
}

func noSched(_ time.Duration, _ interface{}) {}
*/
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
	revData["revoked_at"] = 300000
	rev := &Revocation{Type: "TOKEN", Data: revData, Timestamp: 300000}
	crp.cache.Add(rev)

	// claim
	revData2 := make(map[string]interface{})
	revData2["value_hash"] = hashTokenClaim(subVal)
	revData2["issued_before"] = 200000
	revData2["name"] = sub
	rev2 := &Revocation{Type: "CLAIM", Data: revData2, Timestamp: 200000}
	crp.cache.Add(rev2)

	// global
	revData3 := make(map[string]interface{})
	revData3["issued_before"] = 100000
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

	// Global revocation
	tc["iat"] = 50000.0
	jt = &jwt.Token{Raw: rawJwt, Claims: tc}
	if !crp.IsJWTRevoked(jt) {
		t.Errorf("Token should be revoked (GLOBAL). %#v", jt)
	}

	tc["iat"] = 150000.0
	tc[sub] = "test"
	jt = &jwt.Token{Raw: rawJwt, Claims: tc}
	if crp.IsJWTRevoked(jt) {
		t.Errorf("Token should not be revoked (GLOBAL). %#v", jt)
	}

	// missing 'iat'
	inv := make(map[string]interface{})
	inv[sub] = subVal
	jt = &jwt.Token{Raw: rawJwt, Claims: inv}
	if crp.IsJWTRevoked(jt) {
		t.Errorf("Token should not be revoked (missing 'iat'). %#v", jt)
	}

	// missing 'sub'
	inv = make(map[string]interface{})
	inv["iat"] = 150000.0
	jt = &jwt.Token{Raw: rawJwt, Claims: inv}
	if crp.IsJWTRevoked(jt) {
		t.Errorf("Token should not be revoked (missing 'sub' claim)")
	}

}

func TestIsJWTRevokedMissingCacheFields(t *testing.T) {

	rawJwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6InJyZWlzIiwiYWRtaW4iOnRydWV9.UlZhyvrY9e7tRU88l8sfRb37oWGiL2t4insnO9Nsn1c"
	sub := "sub"
	subVal := "jeff@zalando"

	crp := &CachingRevokeProvider{url: "localhost", cache: NewCache()}

	// token missing revoked_at
	revData := make(map[string]interface{})
	revData["token_hash"] = hashTokenClaim(rawJwt)
	rev := &Revocation{Type: "TOKEN", Data: revData, Timestamp: 300000}
	crp.cache.Add(rev)

	// claim missing issued_before
	revData2 := make(map[string]interface{})
	revData2["value_hash"] = hashTokenClaim(subVal)
	revData2["name"] = sub
	rev2 := &Revocation{Type: "CLAIM", Data: revData2, Timestamp: 200000}
	crp.cache.Add(rev2)

	// global missing issued_before
	revData3 := make(map[string]interface{})
	rev3 := &Revocation{Type: "GLOBAL", Data: revData3, Timestamp: 100000}
	crp.cache.Add(rev3)

	// token
	tc := make(map[string]interface{})
	tc[sub] = subVal
	tc["iat"] = 400000.0
	jt := &jwt.Token{Raw: rawJwt, Claims: tc}

	if crp.IsJWTRevoked(jt) {
		t.Errorf("Token should not be revoked. %#v", jt)
	}

	// claim
	tc["iat"] = 150000.0
	jt = &jwt.Token{Claims: tc}
	if crp.IsJWTRevoked(jt) {
		t.Errorf("Claim should not be revoked. %#v", jt)
	}

	// global
	tc["iat"] = 50000.0
	jt = &jwt.Token{Raw: rawJwt, Claims: tc}
	if crp.IsJWTRevoked(jt) {
		t.Errorf("Token should not be revoked (GLOBAL). %#v", jt)
	}
}

/*
func TestRefreshRevocations(t *testing.T) {

	var listener string

	handler := func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{
				  "meta": {"REFRESH_FROM": 0, "REFRESH_TIMESTAMP": 0},
				    "revocations": [
				    {
			      "type": "CLAIM",
			        "data": {
				        "name": "uid",
				        "value_hash": "+3sDm1MGB3+WGg7CzeMOBwse8V076MyYfNIF1W9A0B0=",
				        "hash_algorithm": "SHA-256",
				        "issued_before": 1456300677
				      },
				      "revoked_at": 1456300677
				    },
				    {
				    "type": "GLOBAL",
				    "data": {
				        "issued_before": 1456296158
				      },
				    "revoked_at": 1456296158
				    },
					{
				    "type": "TOKEN",
				    "data": {
				        "token_hash": "3AW57qxY0oO9RlVOW7zor7uUOFnoTNBSaYbEOYeJPRg=",
				        "hash_algorithm": "SHA-256"
				    },
				    "revoked_at": 1456302443
				    }
				  ]
			}`)

		server := httptest.NewServer(http.HandlerFunc(handler))
		defer server.Close()

		listener = fmt.Sprintf("http://%s", server.Listener.Addr())
		u, _ := url.Parse(listener)
		crp := NewCachingRevokeProvider(u)
		crp.RefreshRevocations()

		if crp.cache.Get("3AW57qxY0oO9RlVOW7zor7uUOFnoTNBSaYbEOYeJPRg=") == nil ||
			crp.cache.Get("uid+3sDm1MGB3+WGg7CzeMOBwse8V076MyYfNIF1W9A0B0=") == nil ||
			crp.cache.Get("GLOBAL") == nil {
			t.Errorf("Should have had three revocations in the cache. . .")
		}
	}
}
*/
// vim: ts=4 sw=4 noexpandtab nolist syn=go
