package keys

import "testing"

func TestDefaultLoader(t *testing.T) {
	kl := DefaultKeyLoader()

	if _, ok := kl.(*cachingOpenIdProviderLoader); !ok {
		t.Errorf("Wrong type for the default key loader %v", kl)
	}
}
