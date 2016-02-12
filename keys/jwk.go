package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

type jsonWebKeySet struct {
	Keys []jsonWebKey `json:"keys"`
}

type jsonWebKey struct {
	Key       interface{}
	KeyId     string
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
	ErrInvalidRSAPublicKey   = errors.New("Invalid RSA Public key")
	ErrInvalidECDSAPublicKey = errors.New("Invalid ECDSA Public key")
)

type base64Bytes []byte

func (b *base64Bytes) UnmarshalJSON(data []byte) error {
	var out string
	if err := json.Unmarshal(data, &out); err != nil {
		return err
	}

	if out == "" {
		return nil
	}

	decoded, err := base64.RawURLEncoding.DecodeString(out)
	if err != nil {
		return err
	}

	*b = base64Bytes(decoded)

	return nil
}

func (b *base64Bytes) toBigInt() *big.Int {
	return new(big.Int).SetBytes([]byte(*b))
}

func (b *base64Bytes) toInt() int {
	return int(b.toBigInt().Int64())
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

// This assumes all keys are pub keys
func (jwk *jsonWebKey) UnmarshalJSON(data []byte) (err error) {
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
		*jwk = jsonWebKey{Key: key, KeyId: buf.Kid, Algorithm: buf.Alg, Use: buf.Use}
	}
	return
}
