package caching

import (
	"reflect"
	"testing"
)

func TestCaching(t *testing.T) {
	cache := NewCache()

	old := cache.Set("foo", "bar")
	if old != nil {
		t.Error("Set returned a non nil value for a new key")
	}

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

	old = cache.Delete("not")
	if old != "in-the-snapshot" {
		t.Error("Delete didn't return the old value")
	}

	v = cache.Get("not")
	if v != nil {
		t.Error("Cache still contained deleted element `not`")
	}

	old = cache.Delete("never-existed")
	if old != nil {
		t.Error("Expected nil from a failed delete")
	}

	oldContent := cache.Clear()
	if len(oldContent) != 1 {
		t.Error("Clear did not return the correct content of the cache")
	}
	if v, has := oldContent["foo"]; !has || v != "bar" {
		t.Error("Unexpected old content. Failed to find the value bar for key foo")
	}

	newContent := cache.Snapshot()
	if len(newContent) != 0 {
		t.Error("Cache should be empty after being cleared")
	}

	cache.Close()
}

type user struct {
	name string
}

func TestSnapshot(t *testing.T) {
	cache := NewCache()
	cache.Set("john", "doe")
	cache.Set("foo", "bar")

	s1 := cache.Snapshot()
	if len(s1) != 2 {
		t.Fatalf("Cache snapshot has wrong len. Expected 2, got %d", len(s1))
	}

	cache.Set("zbr", "xyz")

	s2 := cache.Snapshot()
	if len(s1) == len(s2) {
		t.Error("Both snapshots have the same length")
	}
}

func TestReset(t *testing.T) {
	cache := NewCache()
	cache.Set("john", "doe")
	cache.Set("foo", "bar")

	s1 := cache.Snapshot()

	rst := map[string]interface{}{
		"new-john":  "new-doe",
		"new-foo":   "new-bar",
		"new-stuff": "that-doesnt-matter",
	}
	old := cache.Reset(rst)
	if len(s1) != len(old) {
		t.Error("Old content doesn't match the snapshot")
	}

	if !reflect.DeepEqual(s1, old) {
		t.Error("Old content and snapshot contents don't match")
	}

	s2 := cache.Snapshot()
	if len(s1) == len(s2) {
		t.Error("Both snapshots have the same length")
	}
}

func TestPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != "Unsupported cache operation" {
			t.Error("Recovered from a different error")
		}
	}()
	doOp(nil, &request{op: -1})
}
