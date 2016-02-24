package revoke

import (
	"strconv"
	"testing"
	"time"
)

func TestIsExpiredExpectTrue(t *testing.T) {
	if !isExpired(1) {
		t.Errorf("1970 is a long time ago. This should be expired.")
	}
}

func TestIsExpiredExpectFalse(t *testing.T) {
	if isExpired(20000000000000) {
		t.Errorf("This is a long time from now; it should not be expired.")
	}
}

func TestCaching(t *testing.T) {
	cache := NewCache()

	revData := make(map[string]interface{})
	revData["token_hash"] = "hash"
	revData["revoked_at"] = "123"

	rev := &Revocation{Type: "TOKEN", Data: revData, Timestamp: 234}

	cache.Add(rev)
	if cache.Get("hash") == nil {
		t.Errorf("Failed to find value 'hash' in cache.")
	}

	revData2 := make(map[string]interface{})
	revData2["token_hash"] = "hash2"
	revData2["revoked_at"] = strconv.Itoa(int(time.Now().UnixNano() / 1e6))
	rev2 := &Revocation{Type: "TOKEN", Data: revData2, Timestamp: int(time.Now().UnixNano() / 1e6)}
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
	revData3["revoked_at"] = "20000000"

	rev3 := &Revocation{Type: "TOKEN", Data: revData, Timestamp: 2000000}

	cache.Add(rev3)

	if cache.GetLastTS() != "2000000" {
		t.Errorf("Error getting last pull timestamp. Expected: 2,000,000. Actual: %d", cache.GetLastTS())
	}

}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
