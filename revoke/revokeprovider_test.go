package revoke

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/dgrijalva/jwt-go"

	"testing"
	"time"
)

func init() {
	scheduleFunc = noSched
}

func noSched(_ time.Duration, _ JobFunc) {}

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
	uid := "uid"
	uidVal := "12345"

	crp := &CachingRevokeProvider{url: "localhost", cache: NewCache()}

	// token
	revData := make(map[string]interface{})
	revData["token_hash"] = hashTokenClaim(rawJwt)
	revData["revoked_at"] = 300000
	rev := &Revocation{Type: REVOCATION_TYPE_TOKEN, Data: revData, Timestamp: 300000}
	crp.cache.Add(rev)

	// claim
	revData2 := make(map[string]interface{})
	revData2["value_hash"] = hashTokenClaim(subVal)
	revData2["issued_before"] = 200000
	revData2["names"] = sub
	rev2 := &Revocation{Type: REVOCATION_TYPE_CLAIM, Data: revData2, Timestamp: 200000}
	crp.cache.Add(rev2)

	// global
	revData3 := make(map[string]interface{})
	revData3["issued_before"] = 100000
	rev3 := &Revocation{Type: REVOCATION_TYPE_GLOBAL, Data: revData3, Timestamp: 100000}
	crp.cache.Add(rev3)

	// multi-name claim
	revData4 := make(map[string]interface{})
	revData4["value_hash"] = hashTokenClaim(subVal + "|" + uidVal)
	revData4["issued_before"] = 200000
	revData4["names"] = sub + "|" + uid
	rev4 := &Revocation{Type: REVOCATION_TYPE_CLAIM, Data: revData4, Timestamp: 200000}
	crp.cache.Add(rev4)

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

	// revoke multi-name claim
	tc[uid] = uidVal
	tc["iat"] = 150000.0
	jt = &jwt.Token{Claims: tc}
	if !crp.IsJWTRevoked(jt) {
		t.Errorf("Multi-name claim should be reovked. %v", jt)
	}

	tc["iat"] = 250000.0
	jt = &jwt.Token{Claims: tc}
	if crp.IsJWTRevoked(jt) {
		t.Errorf("Multi-name claim should not be revoked. %#v", jt)
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
	rev := &Revocation{Type: REVOCATION_TYPE_TOKEN, Data: revData, Timestamp: 300000}
	crp.cache.Add(rev)

	// claim missing issued_before
	revData2 := make(map[string]interface{})
	revData2["value_hash"] = hashTokenClaim(subVal)
	revData2["name"] = sub
	rev2 := &Revocation{Type: REVOCATION_TYPE_CLAIM, Data: revData2, Timestamp: 200000}
	crp.cache.Add(rev2)

	// global missing issued_before
	revData3 := make(map[string]interface{})
	rev3 := &Revocation{Type: REVOCATION_TYPE_GLOBAL, Data: revData3, Timestamp: 100000}
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

func TestRefreshRevocations(t *testing.T) {

	var listener string

	j := fmt.Sprintf(`{
				  "meta": {"REFRESH_FROM": 0, "REFRESH_TIMESTAMP": 0},
				    "revocations": [
				    {
			      "type": "CLAIM",
			        "data": {
				        "names": ["uid"],
				        "value_hash": "+3sDm1MGB3+WGg7CzeMOBwse8V076MyYfNIF1W9A0B0=",
				        "hash_algorithm": "SHA-256",
				        "issued_before": %d
				      },
				      "revoked_at": %d
				    },
				    {
				    "type": "GLOBAL",
				    "data": {
				        "issued_before": %d
				      },
				    "revoked_at": %d
				    },
					{
				    "type": "TOKEN",
				    "data": {
				        "token_hash": "3AW57qxY0oO9RlVOW7zor7uUOFnoTNBSaYbEOYeJPRg=",
				        "hash_algorithm": "SHA-256"
				    },
				    "revoked_at": %d
				    }
				  ]
			}`, int(time.Now().Add(-1*time.Hour).Unix()), int(time.Now().Add(-1*time.Hour).Unix()),
		int(time.Now().Add(-2*time.Hour).Unix()), int(time.Now().Add(-2*time.Hour).Unix()),
		int(time.Now().Add(-3*time.Hour).Unix()))

	handler := func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, j)
	}

	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	listener = fmt.Sprintf("http://%s", server.Listener.Addr())
	u, _ := url.Parse(listener)
	crp := NewCachingRevokeProvider(u)
	crp.RefreshRevocations()

	if crp.cache.Get("3AW57qxY0oO9RlVOW7zor7uUOFnoTNBSaYbEOYeJPRg=") == nil ||
		crp.cache.Get("+3sDm1MGB3+WGg7CzeMOBwse8V076MyYfNIF1W9A0B0=") == nil ||
		crp.cache.Get(REVOCATION_TYPE_GLOBAL) == nil {
		t.Errorf("Should have had three revocations in the cache. . .")
	}
}

func TestForceRefresh(t *testing.T) {

	var listener string
	rf := int(time.Now().Add(-4 * time.Hour).Unix())
	rt := int(time.Now().Add(-3 * time.Hour).Unix())
	fr := fmt.Sprintf(`{                                                                                                                                       
	                    "meta": {"REFRESH_FROM": %d, "REFRESH_TIMESTAMP": %d},                                                                                        
	                    "revocations": []                                                                                                                           
		           }`, rf, rt)

	handler := func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, fr)
	}

	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	listener = fmt.Sprintf("http://%s", server.Listener.Addr())
	u, _ := url.Parse(listener)
	crp := NewCachingRevokeProvider(u)

	revData := make(map[string]interface{})
	revData["token_hash"] = "t1"
	revData["revoked_at"] = int(time.Now().Add(-5 * time.Hour).Unix())
	crp.cache.Add(&Revocation{Type: REVOCATION_TYPE_TOKEN, Data: revData, Timestamp: int(time.Now().Add(-4 * time.Hour).Unix())})

	revData = make(map[string]interface{})
	revData["token_hash"] = "t2"
	revData["revoked_at"] = int(time.Now().Add(-4 * time.Hour).Unix())

	crp.cache.Add(&Revocation{Type: REVOCATION_TYPE_TOKEN, Data: revData, Timestamp: int(time.Now().Add(-3 * time.Hour).Unix())})

	revData = make(map[string]interface{})
	revData["value_hash"] = "c1"
	revData["names"] = "c1"
	revData["revoked_at"] = int(time.Now().Add(-3 * time.Hour).Unix())
	crp.cache.Add(&Revocation{Type: REVOCATION_TYPE_CLAIM, Data: revData, Timestamp: int(time.Now().Add(-2 * time.Hour).Unix())})

	revData = make(map[string]interface{})
	revData["value_hash"] = "c2"
	revData["names"] = "c2"
	revData["revoked_at"] = int(time.Now().Add(-2 * time.Hour).Unix())
	crp.cache.Add(&Revocation{Type: REVOCATION_TYPE_CLAIM, Data: revData, Timestamp: int(time.Now().Add(-1 * time.Hour).Unix())})

	revData = make(map[string]interface{})
	revData["value_hash"] = REVOCATION_TYPE_GLOBAL
	revData["revoked_at"] = int(time.Now().Add(-6 * time.Hour).Unix())
	crp.cache.Add(&Revocation{Type: REVOCATION_TYPE_GLOBAL, Data: revData, Timestamp: int(time.Now().Add(-5 * time.Hour).Unix())})

	crp.RefreshRevocations()

	if crp.cache.Get(REVOCATION_TYPE_FORCEREFRESH) == nil {
		t.Errorf("Error force refreshing cache. FORCEREFRESH entry should exist in the cache")
	}
	if ts := crp.cache.GetLastTS(); ts != rt {
		t.Errorf("Error force refreshing cache. Next pull timestamp is incorrect. Expected: %d, Actual: %d", rt, ts)
	}

	if crp.cache.Get("t1") == nil || crp.cache.Get(REVOCATION_TYPE_GLOBAL) == nil {
		t.Errorf("Error force refreshing cache. Revocation 't1' and 'GLOBAL' should exist in cache.")
	}
}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
