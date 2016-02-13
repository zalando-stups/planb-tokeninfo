package jwthandler

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/zalando/planb-tokeninfo/keys"
)

var (
	ErrMissingKeyId = errors.New("Missing key Id in the JWT header")
	ErrInvalidKeyId = errors.New("Invalid key Id in the JWT header")
)

func jwtValidator(kl keys.KeyLoader) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
			return loadKey(kl, token)
		default:
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
	}
}

func loadKey(kl keys.KeyLoader, t *jwt.Token) (interface{}, error) {
	kid, has := t.Header["kid"]

	if !has {
		return nil, ErrMissingKeyId
	}

	id, ok := kid.(string)
	if !ok {
		return nil, ErrInvalidKeyId
	}

	return kl.LoadKey(id)
}
