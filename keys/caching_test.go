package keys

import "testing"

func TestCaching(t *testing.T) {
	cache := NewCache()

	cache.Set("foo", "bar")
	v := cache.Get("foo")
	if v == nil {
		t.Error("Failed to retrieve value for `foo` from cache")
	}

	m := cache.Snapshot()
	cache.Set("not", "in-the-snapshot")
	if len(m) != 1 {
		t.Errorf("Unexpected snapshot content. Wanted 1 element got %d", len(m))
	}

	v = cache.Get("not")
	if v == nil {
		t.Error("Failed to retrieve value for `not` from cache")
	}

	cache.Close()
}
