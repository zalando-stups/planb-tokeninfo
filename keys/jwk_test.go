package keys

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
		want       *JsonWebKeySet
		shouldFail bool
	}{
		{"", nil, true},
		{"{}", &JsonWebKeySet{}, false},
		{`{"foo":"bar"}`, &JsonWebKeySet{}, false},
		{`{"keys":[]}`, &JsonWebKeySet{Keys: make([]JsonWebKey, 0)}, false},
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
			&JsonWebKeySet{Keys: []JsonWebKey{
				JsonWebKey{
					Key: &ecdsa.PublicKey{
						Curve: elliptic.P256(),
						X:     big.NewInt(0x10),
						Y:     big.NewInt(0x10)},
					KeyId:     "testkey",
					Algorithm: "ES256",
					Use:       "sign",
				},
			}}, false,
		},
		{
			`{"keys":[{"alg":"ES384","crv":"P-384","kid":"testkey","kty":"EC","use":"sign","x":"EA","y":"EA"}]}`,
			&JsonWebKeySet{Keys: []JsonWebKey{
				JsonWebKey{
					Key: &ecdsa.PublicKey{
						Curve: elliptic.P384(),
						X:     big.NewInt(0x10),
						Y:     big.NewInt(0x10)},
					KeyId:     "testkey",
					Algorithm: "ES384",
					Use:       "sign",
				},
			}}, false,
		},
		{
			`{"keys":[{"alg":"ES512","crv":"P-521","kid":"testkey","kty":"EC","use":"sign","x":"EA","y":"EA"}]}`,
			&JsonWebKeySet{Keys: []JsonWebKey{
				JsonWebKey{
					Key: &ecdsa.PublicKey{
						Curve: elliptic.P521(),
						X:     big.NewInt(0x10),
						Y:     big.NewInt(0x10)},
					KeyId:     "testkey",
					Algorithm: "ES512",
					Use:       "sign",
				},
			}}, false,
		},
		{
			`{"keys":[{"alg":"RS256","kid":"2011-04-29","kty":"RSA","use":"sign","e":"AQAB","n":"AQAB"}]}`,
			&JsonWebKeySet{Keys: []JsonWebKey{
				JsonWebKey{
					Key: &rsa.PublicKey{
						N: big.NewInt(65537),
						E: 65537},
					KeyId:     "2011-04-29",
					Algorithm: "RS256",
					Use:       "sign",
				},
			}}, false,
		},
	} {
		jwks := new(JsonWebKeySet)
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
