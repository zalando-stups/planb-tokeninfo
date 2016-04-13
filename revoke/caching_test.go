package revoke

import (
	"testing"
	"time"
)

func TestIsExpiredExpectTrue(t *testing.T) {
	if !isExpired(1) {
		t.Errorf("1970 is a long time ago. This should be expired.")
	}
}

func TestIsExpiredExpectFalse(t *testing.T) {
	ti := time.Date(2038, time.January, 1, 0, 0, 0, 0, time.UTC).Unix()

	if isExpired(int(ti)) {
		t.Errorf("This is a long time from now; it should not be expired.")
	}
}

func TestCaching(t *testing.T) {
	cache := NewCache()

	revData := make(map[string]interface{})
	revData["token_hash"] = "hash"
	revData["revoked_at"] = 123
	revData["issued_before"] = 123

	rev := &Revocation{Type: REVOCATION_TYPE_TOKEN, Data: revData}

	cache.Add(rev)
	if cache.Get("hash") == nil {
		t.Errorf("Failed to find value 'hash' in cache.")
	}

	revData2 := make(map[string]interface{})
	revData2["token_hash"] = "hash2"
	revData2["revoked_at"] = int(time.Now().Unix())
	revData2["issued_before"] = int(time.Now().Unix())
	rev2 := &Revocation{Type: REVOCATION_TYPE_TOKEN, Data: revData2}
	cache.Add(rev2)

	cache.Delete("hash2")
	if cache.Get("hash2") != nil {
		t.Errorf("Cache value 'hash2' should be deleted.")
	}

	cache.Expire()
	if cache.Get("hash") != nil {
		t.Errorf("Cache value 'hash' should have expired.")
	}

	revData3 := make(map[string]interface{})
	revData3["token_hash"] = "hash"
	revData3["revoked_at"] = 20000000
	revData3["issued_before"] = 20000000

	rev3 := &Revocation{Type: REVOCATION_TYPE_TOKEN, Data: revData3}

	cache.Add(rev3)

	if cache.GetLastTS() != 20000000 {
		t.Errorf("Error getting last pull timestamp. Expected: 2000000. Actual: %d", cache.GetLastTS())
	}

	if len(cache.GetClaimNames()) != 0 {
		t.Errorf("Shouldn't have any claim names as there aren't any in the cache. ClaimNames: %#v", cache.GetClaimNames())
	}

	revData4 := make(map[string]interface{})
	revData4["value_hash"] = "hash4"
	revData4["names"] = "claimName4"
	revData4["revoked_at"] = int(time.Now().Unix())
	rev4 := &Revocation{Type: REVOCATION_TYPE_CLAIM, Data: revData4}
	cache.Add(rev4)

	revData5 := make(map[string]interface{})
	revData5["value_hash"] = "hash5"
	revData5["names"] = "claimName5"
	revData5["revoked_at"] = int(time.Now().Unix())
	rev5 := &Revocation{Type: REVOCATION_TYPE_CLAIM, Data: revData5}
	cache.Add(rev5)

	revData6 := make(map[string]interface{})
	revData6["value_hash"] = "hash6"
	revData6["names"] = "claimName5"
	revData6["revoked_at"] = int(time.Now().Unix())
	rev6 := &Revocation{Type: REVOCATION_TYPE_CLAIM, Data: revData6}
	cache.Add(rev6)

	if len(cache.GetClaimNames()) != 2 {
		t.Errorf("Should have two claim names. ClaimNames: %#v", cache.GetClaimNames())
	}

}

func TestCachingMissingRevocationValues(t *testing.T) {

	cache := NewCache()

	// missing token_hash
	revData := make(map[string]interface{})
	revData["revoked_at"] = int(time.Now().Unix())
	revData["issued_before"] = int(time.Now().Unix())

	rev := &Revocation{Type: REVOCATION_TYPE_TOKEN, Data: revData}

	cache.Add(rev)
	if cache.GetLastTS() != 0 {
		t.Errorf("Cache should be empty.")
	}

	// missing claim name
	revData1 := make(map[string]interface{})
	revData1["value_hash"] = "hash1"
	revData1["revoked_at"] = int(time.Now().Unix())
	rev1 := &Revocation{Type: REVOCATION_TYPE_CLAIM, Data: revData1}

	cache.Add(rev1)

	if cache.GetLastTS() != 0 {
		t.Errorf("Cache should be empty.")
	}

	// missing claim value_hash
	revData2 := make(map[string]interface{})
	revData2["names"] = "names"
	revData2["revoked_at"] = int(time.Now().Unix())
	rev2 := &Revocation{Type: REVOCATION_TYPE_CLAIM, Data: revData2}

	cache.Add(rev2)

	if cache.GetLastTS() != 0 {
		t.Errorf("Cache should be empty.")
	}

	// missing type
	revData3 := make(map[string]interface{})
	revData3["revoked_at"] = int(time.Now().Unix())
	revData3["token_hash"] = "token"
	revData3["value_hash"] = "value"
	revData3["names"] = "names"
	rev3 := &Revocation{Type: "", Data: revData3}

	cache.Add(rev3)

	if cache.GetLastTS() != 0 {
		t.Errorf("Cache should be empty")
	}
}

func TestCachingForceRefresh(t *testing.T) {
	cache := NewCache()

	revData := make(map[string]interface{})
	revData["token_hash"] = "t1"
	revData["revoked_at"] = int(time.Now().Add(-1 * time.Hour).Unix())
	revData["issued_before"] = int(time.Now().Add(-1 * time.Hour).Unix())
	cache.Add(&Revocation{Type: REVOCATION_TYPE_TOKEN, Data: revData})

	revData = make(map[string]interface{})
	revData["token_hash"] = "t2"
	revData["revoked_at"] = int(time.Now().Add(-3 * time.Hour).Unix())
	revData["issued_before"] = int(time.Now().Add(-3 * time.Hour).Unix())
	cache.Add(&Revocation{Type: REVOCATION_TYPE_TOKEN, Data: revData})

	revData = make(map[string]interface{})
	revData["value_hash"] = "c1"
	revData["names"] = "c1"
	revData["revoked_at"] = int(time.Now().Add(-1 * time.Hour).Unix())
	cache.Add(&Revocation{Type: REVOCATION_TYPE_CLAIM, Data: revData})

	revData = make(map[string]interface{})
	revData["value_hash"] = "c2"
	revData["names"] = "c2"
	revData["revoked_at"] = int(time.Now().Add(-3 * time.Hour).Unix())
	cache.Add(&Revocation{Type: REVOCATION_TYPE_CLAIM, Data: revData})

	revData = make(map[string]interface{})
	revData["value_hash"] = REVOCATION_TYPE_GLOBAL
	revData["revoked_at"] = int(time.Now().Add(-1 * time.Hour).Unix())
	cache.Add(&Revocation{Type: REVOCATION_TYPE_GLOBAL, Data: revData})

	cache.ForceRefresh(0)

	if cache.Get("t1") == nil ||
		cache.Get("t2") == nil ||
		cache.Get("c1") == nil ||
		cache.Get("c2") == nil ||
		cache.Get(REVOCATION_TYPE_GLOBAL) == nil {
		t.Errorf("Force refresh should not have removed any elements.")
	}

	cache.ForceRefresh(int(time.Now().Unix()))

	if cache.Get("t1") == nil ||
		cache.Get("t2") == nil ||
		cache.Get("c1") == nil ||
		cache.Get("c2") == nil ||
		cache.Get(REVOCATION_TYPE_GLOBAL) == nil {
		t.Errorf("Force refresh should not have removed any elements.")
	}

	cache.ForceRefresh(int(time.Now().Add(-2 * time.Hour).Unix()))

	if cache.Get("t1") != nil ||
		cache.Get("t2") == nil ||
		cache.Get("c1") != nil ||
		cache.Get("c2") == nil ||
		cache.Get(REVOCATION_TYPE_GLOBAL) != nil {
		t.Errorf("Force refresh should not have removed token t2 and claim c2.")
	}

	cache.ForceRefresh(int(time.Now().Add(-4 * time.Hour).Unix()))

	if cache.Get("t1") != nil ||
		cache.Get("t2") != nil ||
		cache.Get("c1") != nil ||
		cache.Get("c2") != nil ||
		cache.Get(REVOCATION_TYPE_GLOBAL) != nil {
		t.Errorf("Force refresh should have removed all cached elements.")
	}

}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
