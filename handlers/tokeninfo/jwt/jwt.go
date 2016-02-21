package jwthandler

import (
	"errors"
	"fmt"

	"github.com/dgrijalva/jwt-go"
	"github.com/zalando/planb-tokeninfo/keyloader"
)

var (
	// ErrMissingKeyID should be used when the kid attribute is missing in the JWT header
	ErrMissingKeyID = errors.New("Missing key Id in the JWT header")
	// ErrInvalidKeyID should be used when the content of the kid attribute is invalid
	ErrInvalidKeyID = errors.New("Invalid key Id in the JWT header")
)

func jwtValidator(kl keyloader.KeyLoader) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
			return loadKey(kl, token)
		default:
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
	}
}

func loadKey(kl keyloader.KeyLoader, t *jwt.Token) (interface{}, error) {
	kid, has := t.Header["kid"]

	if !has {
		return nil, ErrMissingKeyID
	}

	id, ok := kid.(string)
	if !ok {
		return nil, ErrInvalidKeyID
	}

	return kl.LoadKey(id)
}
