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
	if isExpired(2000000000) {
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

	cache.Delete("hash")
	if len(cache.set) != 0 {
		t.Errorf("Error deleting 'hash' from cache.")
	}

	cache.Add(rev)
	cache.Expire()
	time.Sleep(1 * time.Second)

	if len(cache.set) != 0 {
		t.Errorf("Error deleting 'hash' from cache.")
	}
}
