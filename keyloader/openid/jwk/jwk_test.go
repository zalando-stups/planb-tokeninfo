package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"reflect"
	"testing"
)

func TestJwk(t *testing.T) {
	for _, test := range []struct {
		input      string
		want       *JSONWebKeySet
		shouldFail bool
	}{
		{"", nil, true},
		{"{}", &JSONWebKeySet{}, false},
		{`{"foo":"bar"}`, &JSONWebKeySet{}, false},
		{`{"keys":[]}`, &JSONWebKeySet{Keys: make([]JSONWebKey, 0)}, false},
		{`{"keys":[{"kty":"FOO"}]}`, nil, true},
		{`{"keys":[{:}]}`, nil, true},
		{`{"keys":[{"alg":"ESXXX","crv":"P-FOO","kid":"testkey","kty":"EC","use":"sign","x":"EA","y":"EA"}]}`, nil, true},
		{`{"keys":[{"alg":"ES256","crv":"P-256","kid":"testkey","kty":"EC","use":"sign"}]}`, nil, true},
		{`{"keys":[{"alg":"ES256","crv":"P-256","kid":"testkey","kty":"EC","use":"sign","x":"EA"}]}`, nil, true},
		{`{"keys":[{"alg":"ES256","crv":"P-256","kid":"testkey","kty":"EC","use":"sign","y":"EA"}]}`, nil, true},
		{`{"keys":[{"alg":"RS256","kid":"2011-04-29","kty":"RSA","use":"sign"}]}`, nil, true},
		{`{"keys":[{"alg":"RS256","kid":"2011-04-29","kty":"RSA","use":"sign","e":"AQAB"}]}`, nil, true},
		{`{"keys":[{"alg":"RS256","kid":"2011-04-29","kty":"RSA","use":"sign","n":"AQAB"}]}`, nil, true},
		{`{"keys":[{"alg":"RS256","kid":"2011-04-29","kty":"RSA","use":"sign","n":"-"}]}`, nil, true},
		{
			`{"keys":[{"alg":"ES256","crv":"P-256","kid":"testkey","kty":"EC","use":"sign","x":"EA","y":"EA"}]}`,
			&JSONWebKeySet{Keys: []JSONWebKey{
				{
					Key: &ecdsa.PublicKey{
						Curve: elliptic.P256(),
						X:     big.NewInt(0x10),
						Y:     big.NewInt(0x10)},
					KeyID:     "testkey",
					Algorithm: "ES256",
					Use:       "sign",
				},
			}}, false,
		},
		{
			`{"keys":[{"alg":"ES384","crv":"P-384","kid":"testkey","kty":"EC","use":"sign","x":"EA","y":"EA"}]}`,
			&JSONWebKeySet{Keys: []JSONWebKey{
				{
					Key: &ecdsa.PublicKey{
						Curve: elliptic.P384(),
						X:     big.NewInt(0x10),
						Y:     big.NewInt(0x10)},
					KeyID:     "testkey",
					Algorithm: "ES384",
					Use:       "sign",
				},
			}}, false,
		},
		{
			`{"keys":[{"alg":"ES512","crv":"P-521","kid":"testkey","kty":"EC","use":"sign","x":"EA","y":"EA"}]}`,
			&JSONWebKeySet{Keys: []JSONWebKey{
				{
					Key: &ecdsa.PublicKey{
						Curve: elliptic.P521(),
						X:     big.NewInt(0x10),
						Y:     big.NewInt(0x10)},
					KeyID:     "testkey",
					Algorithm: "ES512",
					Use:       "sign",
				},
			}}, false,
		},
		{
			`{"keys":[{"alg":"RS256","kid":"2011-04-29","kty":"RSA","use":"sign","e":"AQAB","n":"AQAB"}]}`,
			&JSONWebKeySet{Keys: []JSONWebKey{
				{
					Key: &rsa.PublicKey{
						N: big.NewInt(65537),
						E: 65537},
					KeyID:     "2011-04-29",
					Algorithm: "RS256",
					Use:       "sign",
				},
			}}, false,
		},
	} {
		jwks := new(JSONWebKeySet)
		if err := json.Unmarshal([]byte(test.input), jwks); err == nil {
			if !reflect.DeepEqual(jwks, test.want) {
				println()
				t.Error("Unpexpected decoding result: ", jwks)
			}
		} else if !test.shouldFail {
			t.Error("Failed to parse JWKS: ", err)
		}
	}
}

func TestToMap(t *testing.T) {
	tenBigInt := big.NewInt(0x10)

	jwks := JSONWebKeySet{
		Keys: []JSONWebKey{
			{
				Key: &rsa.PublicKey{
					N: tenBigInt,
					E: 0x20},
				KeyID:     "key1",
				Algorithm: "RS256",
				Use:       "sign",
			},
			{
				Key: &ecdsa.PublicKey{
					Curve: elliptic.P256(),
					X:     tenBigInt,
					Y:     tenBigInt},
				KeyID:     "key2",
				Algorithm: "ES256",
				Use:       "sign",
			},
			{
				Key: &rsa.PublicKey{
					N: tenBigInt,
					E: 0x20},
				KeyID:     "key2",
				Algorithm: "RS256",
				Use:       "sign",
			},
		},
	}
	m := jwks.ToMap()

	if len(m) != 2 {
		t.Error("Wrong map size. Expected 2 but got ", len(m))
	}

	v, has := m["key1"]
	if !has {
		t.Error("Could not find RSA key with key id 'key1'")
	}

	key1, ok := v.(JSONWebKey)
	if !ok {
		t.Errorf("Wrong type for 'key1'. Expected JsonWebKey, got %T", v)
	}

	rsaPkey, ok := key1.Key.(*rsa.PublicKey)
	if !ok {
		t.Errorf("Wrong type of pubkey for 'key1'. Expected RSA, got %T", key1.Key)
	}

	if rsaPkey.E != 0x20 || rsaPkey.N != tenBigInt {
		t.Error("Wrong parameters for RSA key 'key1'")
	}

	v, has = m["key2"]
	if !has {
		t.Error("Could not find ECDSA key with key id 'key2'")
	}

	key2, ok := v.(JSONWebKey)
	if !ok {
		t.Errorf("Wrong type for 'key2'. Expected JsonWebKey, got %T", v)
	}

	ecdsaPkey, ok := key2.Key.(*ecdsa.PublicKey)
	if !ok {
		t.Errorf("Wrong type of pubkey for 'key2'. Expected ECDSA, got %T", key2)
	}

	if ecdsaPkey.X != tenBigInt || ecdsaPkey.Y != tenBigInt {
		t.Error("Wrong parameters for ECDSA key 'key2'")
	}

}
