package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log"
)

// The JSONWebKeySet is an helper type to unmarshal te JSON response from an OpenID JWKS endpoint
type JSONWebKeySet struct {
	Keys []JSONWebKey `json:"keys"`
}

// The JSONWebKey is a type that holds keys obtained from a JWKS endpoint
type JSONWebKey struct {
	Key       interface{}
	KeyID     string
	Algorithm string
	Use       string
}

type jsonWebKeyHelper struct {
	Use string       `json:"use,omitempty"`
	Kty string       `json:"kty,omitempty"`
	Kid string       `json:"kid,omitempty"`
	Crv string       `json:"crv,omitempty"`
	Alg string       `json:"alg,omitempty"`
	K   *base64Bytes `json:"k,omitempty"`
	X   *base64Bytes `json:"x,omitempty"`
	Y   *base64Bytes `json:"y,omitempty"`
	N   *base64Bytes `json:"n,omitempty"`
	E   *base64Bytes `json:"e,omitempty"`
}

var (
	// ErrInvalidRSAPublicKey should be used whenever the key thumbprint is an invalid RSA key
	ErrInvalidRSAPublicKey = errors.New("Invalid RSA Public key")
	// ErrInvalidECDSAPublicKey should be used whenever the key thumbprint is an invalid ECDSA key
	ErrInvalidECDSAPublicKey = errors.New("Invalid ECDSA Public key")
)

// ToMap returns the JSON Web Keys Set as a simple map with the Key IDs as keys of the map and the
// JSON Web Keys as their respective values. The map rejects any duplicates from the JSON Web Keys Set
// http://tools.ietf.org/html/draft-ietf-jose-json-web-key-05#section-5
func (jwks *JSONWebKeySet) ToMap() map[string]interface{} {
	m := make(map[string]interface{})
	for _, k := range jwks.Keys {
		if _, has := m[k.KeyID]; has {
			log.Printf("Duplicate key %q. Rejecting\n", k.KeyID)
			continue
		}
		m[k.KeyID] = k
	}
	return m
}

func (key *jsonWebKeyHelper) toRSA() (*rsa.PublicKey, error) {
	if key.N == nil || key.E == nil {
		return nil, ErrInvalidRSAPublicKey
	}

	return &rsa.PublicKey{
		N: key.N.toBigInt(),
		E: key.E.toInt(),
	}, nil
}

func (key *jsonWebKeyHelper) toECDSA() (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch key.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("Unsupported ECDSA elliptic curve '%s'", key.Crv)
	}

	if key.X == nil || key.Y == nil {
		return nil, ErrInvalidECDSAPublicKey
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     key.X.toBigInt(),
		Y:     key.Y.toBigInt(),
	}, nil
}

// UnmarshalJSON is used to unmarshal a JWK entry from the JSON Web Keys Set
// It assumes all keys from that endpoint are public keys. Only RSA and ECDSA keys are supported
func (jwk *JSONWebKey) UnmarshalJSON(data []byte) (err error) {
	var buf jsonWebKeyHelper
	if err = json.Unmarshal(data, &buf); err != nil {
		return err
	}
	var key interface{}
	switch buf.Kty {
	case "EC":
		key, err = buf.toECDSA()
	case "RSA":
		key, err = buf.toRSA()
	default:
		err = fmt.Errorf("Unsupported key type %q", buf.Kty)
	}

	if err == nil {
		*jwk = JSONWebKey{Key: key, KeyID: buf.Kid, Algorithm: buf.Alg, Use: buf.Use}
	}
	return
}
