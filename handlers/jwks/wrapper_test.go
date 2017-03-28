package jwks

import (
	"crypto/dsa"
	"encoding/json"
	"testing"

	"github.com/zalando/planb-tokeninfo/keyloader/openid/jwk"
)

func TestWrapper(t *testing.T) {
	kl := &mockKeyLoader{theKeys: mockValidKeys()}
	wrapper := &jwksWrapper{
		keys: kl.Keys(),
	}

	b, err := json.Marshal(wrapper)
	if err != nil {
		t.Error("Failed to marshal the JWKS Wrapper: ", err)
	}

	m := make(map[string]interface{})
	if err := json.Unmarshal(b, &m); err != nil {
		t.Error("Failed to recover the serialized result: ", err)
	}

	a, has := m["keys"]
	if !has {
		t.Error("Failed to recover the original keys entry")
	}

	keys, ok := a.([]interface{})
	if !ok {
		t.Error("Content doesn't contain a list of keys")
	}

	if len(keys) != 2 {
		t.Errorf("Unexpected amount of keys in the response. Wanted 2, got %d\n", len(keys))
	}

	commonAttrs := []string{"alg", "use", "kty"}
	for _, km := range keys {
		key, ok := km.(map[string]interface{})
		if !ok {
			t.Errorf("Failed to recover the key map for key %q\n", km)
		}
		for _, commonAttr := range commonAttrs {
			if _, has := key[commonAttr]; !has {
				t.Errorf("Recovered key missed the %q common attribute", commonAttr)
			}
		}

		switch key["kty"] {
		case "RSA":
			if alg, has := key["alg"]; !has || alg != "RS256" {
				t.Errorf("Invalid/Missing algorithm for RSA key %q. Wanted RS256, got %q", key["kid"], key["alg"])
			}
			if e, has := key["e"]; !has || e != "AQAB" {
				t.Errorf("Invalid/Missing public exponent `e` for RSA key %q. Wanted AQAB, got %q", key["kid"], key["e"])
			}
			if n, has := key["n"]; !has || n != rsaModulus {
				t.Errorf("Invalid/Missing modulus `n` for RSA key %q. Wanted %q, got %q", key["kid"], rsaModulus, key["n"])
			}
		case "EC":
			if alg, has := key["alg"]; !has || alg != "ES256" {
				t.Errorf("Invalid/Missing algorithm for ECDSA key %q. Wanted ESA256, got %q", key["kid"], key["alg"])
			}
			if x, has := key["x"]; !has || x != ecdsaX {
				t.Errorf("Invalid/Missing X coordinate for ECDSA key %q. Wanted %q, got %q", key["kid"], ecdsaX, key["e"])
			}
			if y, has := key["y"]; !has || y != ecdsaY {
				t.Errorf("Invalid/Missing Y coordinate for ECDSA key %q. Wanted %q, got %q", key["kid"], ecdsaY, key["n"])
			}
		default:
			t.Errorf("Recovered key %q has an invalid algorithm: %q", key["kid"], key["kty"])
		}
	}
}

func TestFailures(t *testing.T) {
	jwk := jwk.JSONWebKey{
		Algorithm: "ERROR",
		Use:       "sig",
		KeyID:     "key3",
		Key:       &dsa.PublicKey{},
	}

	if _, err := fromJwk(jwk); err == nil {
		t.Error("Expected failure due to unknown key type")
	}

	if _, err := json.Marshal(&jwksWrapper{keys: map[string]interface{}{"foo": "bar"}}); err == nil {
		t.Error("Expected failure due to unknown key map entry")
	}

	w := &jwksWrapper{
		keys: map[string]interface{}{
			"key3": jwk,
		},
	}
	if _, err := json.Marshal(w); err == nil {
		t.Error("Expected failure due to unknown key map entry")
	}

}
