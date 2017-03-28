package jwks

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"

	"github.com/zalando/planb-tokeninfo/keyloader/openid/jwk"
)

type jwksWrapper struct {
	keys map[string]interface{}
}

func (j *jwksWrapper) MarshalJSON() ([]byte, error) {
	keys := make([]map[string]string, len(j.keys))
	i := 0
	for k, v := range j.keys {
		key, ok := v.(jwk.JSONWebKey)
		if !ok {
			fmt.Printf("Key %q is not a JWK\n", k)
			return nil, fmt.Errorf("Invalid JWK: %v\n", v)
		}
		m, err := fromJwk(key)
		if err != nil {
			fmt.Printf("Failed to convert the JWK %v to a map: %v\n", key, err)
			return nil, err
		}
		keys[i] = m
		i++
	}
	return json.Marshal(map[string][]map[string]string{"keys": keys})
}

func fromJwk(k jwk.JSONWebKey) (map[string]string, error) {
	m := map[string]string{
		"use": k.Use,
		"kid": k.KeyID,
		"alg": k.Algorithm,
	}
	switch key := k.Key.(type) {
	case *ecdsa.PublicKey:
		ecThumbprintInput(m, key)
	case *rsa.PublicKey:
		rsaThumbprintInput(m, key)
	default:
		return nil, fmt.Errorf("Unkown key type %q", reflect.TypeOf(key))
	}
	return m, nil
}

func ecThumbprintInput(m map[string]string, pkey *ecdsa.PublicKey) {
	m["kty"] = "EC"
	m["crv"] = pkey.Curve.Params().Name
	m["x"] = base64.RawURLEncoding.EncodeToString(pkey.X.Bytes())
	m["y"] = base64.RawURLEncoding.EncodeToString(pkey.Y.Bytes())
}

func rsaThumbprintInput(m map[string]string, pkey *rsa.PublicKey) {
	m["kty"] = "RSA"
	m["e"] = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pkey.E)).Bytes())
	m["n"] = base64.RawURLEncoding.EncodeToString(pkey.N.Bytes())
}
