package revoke

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"

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
	revData["revoked_at"] = 500000
	revData["issued_before"] = 500000
	rev := &Revocation{Type: REVOCATION_TYPE_TOKEN, Data: revData}
	crp.cache.Add(rev)

	// claim
	revData2 := make(map[string]interface{})
	revData2["value_hash"] = hashTokenClaim(subVal)
	revData2["issued_before"] = 200000
	revData2["revoked_at"] = 200000
	revData2["names"] = sub
	rev2 := &Revocation{Type: REVOCATION_TYPE_CLAIM, Data: revData2}
	crp.cache.Add(rev2)

	// global
	revData3 := make(map[string]interface{})
	revData3["issued_before"] = 100000
	revData3["revoked_at"] = 100000
	rev3 := &Revocation{Type: REVOCATION_TYPE_GLOBAL, Data: revData3}
	crp.cache.Add(rev3)

	// multi-name claim
	revData4 := make(map[string]interface{})
	revData4["value_hash"] = hashTokenClaim(subVal + "|" + uidVal)
	revData4["issued_before"] = 200000
	revData4["revoked_at"] = 20000
	revData4["names"] = sub + "|" + uid
	rev4 := &Revocation{Type: REVOCATION_TYPE_CLAIM, Data: revData4}
	crp.cache.Add(rev4)

	// revoke a token
	tc := jwt.MapClaims{}
	tc[sub] = subVal
	tc["iat"] = 400000.0
	jt := &jwt.Token{Raw: rawJwt, Claims: tc}

	if !crp.IsJWTRevoked(jt) {
		t.Errorf("Token should be revoked. %#v", jt)
	}

	tc["iat"] = 550000.0
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
	inv := jwt.MapClaims{}
	inv[sub] = subVal
	jt = &jwt.Token{Raw: rawJwt, Claims: inv}
	if crp.IsJWTRevoked(jt) {
		t.Errorf("Token should not be revoked (missing 'iat'). %#v", jt)
	}

	// missing 'sub'
	inv = jwt.MapClaims{}
	inv["iat"] = 150000.0
	jt = &jwt.Token{Raw: rawJwt, Claims: inv}
	if crp.IsJWTRevoked(jt) {
		t.Errorf("Token should not be revoked (missing 'sub' claim)")
	}

	// Test JWT with nil claims
	jt = &jwt.Token{}
	if crp.IsJWTRevoked(jt) {
		t.Errorf("Claim should not be revoked. %#v", jt)
	}

}

func TestIsJWTRevokedMissingCacheFields(t *testing.T) {

	rawJwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwibmFtZSI6InJyZWlzIiwiYWRtaW4iOnRydWV9.UlZhyvrY9e7tRU88l8sfRb37oWGiL2t4insnO9Nsn1c"
	sub := "sub"
	subVal := "jeff@zalando"

	crp := &CachingRevokeProvider{url: "localhost", cache: NewCache()}

	// token missing issued_before
	revData := make(map[string]interface{})
	revData["token_hash"] = hashTokenClaim(rawJwt)
	revData["revoked_at"] = 300000
	rev := &Revocation{Type: REVOCATION_TYPE_TOKEN, Data: revData}
	crp.cache.Add(rev)

	// claim missing issued_before
	revData2 := make(map[string]interface{})
	revData2["value_hash"] = hashTokenClaim(subVal)
	revData2["name"] = sub
	revData2["revoked_at"] = 100000
	rev2 := &Revocation{Type: REVOCATION_TYPE_CLAIM, Data: revData2}
	crp.cache.Add(rev2)

	// global missing issued_before
	revData3 := make(map[string]interface{})
	revData3["revoked_at"] = 100000
	rev3 := &Revocation{Type: REVOCATION_TYPE_GLOBAL, Data: revData3}
	crp.cache.Add(rev3)

	// token
	tc := jwt.MapClaims{}
	tc[sub] = subVal
	tc["iat"] = 200000.0
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
				        "hash_algorithm": "SHA-256",
						"issued_before": %d
				    },
				    "revoked_at": %d
				    }
				  ]
			}`, int(time.Now().Add(-1*time.Hour).Unix()), int(time.Now().Add(-1*time.Hour).Unix()),
		int(time.Now().Add(-2*time.Hour).Unix()), int(time.Now().Add(-2*time.Hour).Unix()),
		int(time.Now().Add(-3*time.Hour).Unix()), int(time.Now().Add(-3*time.Hour).Unix()))

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

func TestRefreshRevocationsDisallowFuture(t *testing.T) {

	var listener string

	now := int(time.Now().Unix())
	future := now + 300
	past := now - 300

	j := fmt.Sprintf(`{
				  "meta": {"REFRESH_FROM": 0, "REFRESH_TIMESTAMP": 0},
				    "revocations": [
				    {
			      "type": "CLAIM",
			        "data": {
				        "names": ["uid"],
				        "value_hash": "infuture",
				        "hash_algorithm": "SHA-256",
				        "issued_before": %d
				      },
				      "revoked_at": %d
				    },
				    {
			      "type": "CLAIM",
			        "data": {
				        "names": ["uid"],
				        "value_hash": "inpast",
				        "hash_algorithm": "SHA-256",
				        "issued_before": %d
				      },
				      "revoked_at": %d
				    }
				  ]
			}`,
		future,
		now,
		past,
		now)

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

	if crp.cache.Get("inpast") == nil {
		t.Errorf("Revocation of old tokens should work")
	}

	if crp.cache.Get("infuture") != nil {
		t.Errorf("Revocation of future tokens should not work")
	}
}

func TestRefreshRevocationsInvalidJSON(t *testing.T) {

	var listener string

	j := fmt.Sprintf(`{
						Invalid JSON
					}`)

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

	if crp.cache.GetLastTS() != 0 {
		t.Errorf("Expecting invalid JSON. Should have 0 entries in the cache.")
	}
}

func TestRefreshRevocationsBadHTTPStatus(t *testing.T) {

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
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, j)
	}

	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	listener = fmt.Sprintf("http://%s", server.Listener.Addr())
	u, _ := url.Parse(listener)
	crp := NewCachingRevokeProvider(u)
	crp.RefreshRevocations()

	if crp.cache.GetLastTS() != 0 {
		t.Errorf("Expecting invalid JSON. Should have 0 entries in the cache.")
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
	revData["issued_before"] = int(time.Now().Add(-5 * time.Hour).Unix())
	crp.cache.Add(&Revocation{Type: REVOCATION_TYPE_TOKEN, Data: revData})

	revData = make(map[string]interface{})
	revData["token_hash"] = "t2"
	revData["revoked_at"] = int(time.Now().Add(-4 * time.Hour).Unix())
	revData["issued_before"] = int(time.Now().Add(-4 * time.Hour).Unix())

	crp.cache.Add(&Revocation{Type: REVOCATION_TYPE_TOKEN, Data: revData})

	revData = make(map[string]interface{})
	revData["value_hash"] = "c1"
	revData["names"] = "c1"
	revData["revoked_at"] = int(time.Now().Add(-3 * time.Hour).Unix())
	crp.cache.Add(&Revocation{Type: REVOCATION_TYPE_CLAIM, Data: revData})

	revData = make(map[string]interface{})
	revData["value_hash"] = "c2"
	revData["names"] = "c2"
	revData["revoked_at"] = int(time.Now().Add(-2 * time.Hour).Unix())
	crp.cache.Add(&Revocation{Type: REVOCATION_TYPE_CLAIM, Data: revData})

	revData = make(map[string]interface{})
	revData["value_hash"] = REVOCATION_TYPE_GLOBAL
	revData["revoked_at"] = int(time.Now().Add(-6 * time.Hour).Unix())
	crp.cache.Add(&Revocation{Type: REVOCATION_TYPE_GLOBAL, Data: revData})

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

// benchmarks are checking a valid JWT to ensure that all revocation types are called on each iteration.
func benchmarkIsJWTRevoked(i int, cNames []string, b *testing.B) {

	var listener string
	fr := fmt.Sprintf(`{}`)

	handler := func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, fr)
	}

	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	listener = fmt.Sprintf("http://%s", server.Listener.Addr())
	u, _ := url.Parse(listener)
	crp := NewCachingRevokeProvider(u)

	for uid := 1; uid <= i; uid++ {
		rd := jwt.MapClaims{}
		rd["value_hash"] = strconv.Itoa(uid)
		rd["names"] = cNames[uid%len(cNames)]
		rd["revoked_at"] = int(time.Now().Unix())

		crp.cache.Add(&Revocation{Type: REVOCATION_TYPE_CLAIM, Data: rd})
	}

	jc := jwt.MapClaims{}
	jc["uid"] = "UserId"
	jc["realm"] = "/customers"
	jc["scope"] = "[uid]"
	jc["iss"] = "Benchmark"
	jc["sub"] = "subject"
	jc["iat"] = float64(time.Now().Unix())
	jt := &jwt.Token{Raw: "NotARealHash", Claims: jc}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		crp.IsJWTRevoked(jt)
	}
}

func benchmarkIsJWTRevokedRevocations(i int, b *testing.B) {
	cNames := []string{"uid",
		"uid|realm",
		"uid|scope",
		"uid|iss"}
	benchmarkIsJWTRevoked(i, cNames, b)
}

func benchmarkIsJWTRevokedClaimNames(cNames []string, b *testing.B) {
	benchmarkIsJWTRevoked(100000, cNames, b)
}

// Revocation Benchmarks are using 4 claim names and differing number of revocations
func BenchmarkIsJWTRevokedRevocations10K(b *testing.B) {
	benchmarkIsJWTRevokedRevocations(10000, b)
}

func BenchmarkIsJWTRevokedRevocations100K(b *testing.B) {
	benchmarkIsJWTRevokedRevocations(100000, b)
}

func BenchmarkIsJWTRevokedRevocations1M(b *testing.B) {
	benchmarkIsJWTRevokedRevocations(1000000, b)
}

func BenchmarkIsJWTRevokedRevocations2M(b *testing.B) {
	benchmarkIsJWTRevokedRevocations(2000000, b)
}

func BenchmarkIsJWTRevokedRevocations3M(b *testing.B) {
	benchmarkIsJWTRevokedRevocations(3000000, b)
}

func BenchmarkIsJWTRevokedRevocations4M(b *testing.B) {
	benchmarkIsJWTRevokedRevocations(4000000, b)
}

func BenchmarkIsJWTRevokedRevocations5M(b *testing.B) {
	benchmarkIsJWTRevokedRevocations(5000000, b)
}

// Claim name benchmarks are using a differing number of claim names and a static number of revocations (100K).
func BenchmarkIsJWTRevokedClaimNames5(b *testing.B) {
	cNames := []string{"uid",
		"uid|realm",
		"uid|scope",
		"uid|iss",
		"realm"}
	benchmarkIsJWTRevokedClaimNames(cNames, b)
}

func BenchmarkIsJWTRevokedClaimNames10(b *testing.B) {
	cNames := []string{"uid",
		"uid|realm",
		"uid|scope",
		"uid|iss",
		"realm",
		"scope",
		"iss",
		"sub",
		"realm|scope",
		"realm|iss"}
	benchmarkIsJWTRevokedClaimNames(cNames, b)
}

func BenchmarkIsJWTRevokedClaimNames15(b *testing.B) {
	//Note: order of each name matters (e.g. uid|realm is not the same as realm|uid)
	cNames := []string{"uid",
		"uid|realm",
		"uid|scope",
		"uid|iss",
		"realm",
		"scope",
		"iss",
		"sub",
		"realm|scope",
		"realm|iss",
		"realm|sub",
		"realm|uid",
		"scope|uid",
		"scope|real",
		"scope|iss"}
	benchmarkIsJWTRevokedClaimNames(cNames, b)
}

func BenchmarkIsJWTRevokedClaimNames20(b *testing.B) {
	//Note: order of each name matters (e.g. uid|realm is not the same as realm|uid)
	cNames := []string{"uid",
		"uid|realm",
		"uid|scope",
		"uid|iss",
		"realm",
		"scope",
		"iss",
		"sub",
		"realm|scope",
		"realm|iss",
		"realm|sub",
		"realm|uid",
		"scope|uid",
		"scope|real",
		"scope|iss",
		"scope|sub",
		"iss|uid",
		"iss|realm",
		"iss|scope",
		"iss|sub"}
	benchmarkIsJWTRevokedClaimNames(cNames, b)
}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
