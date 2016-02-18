package jwthandler

import (
	"testing"

	"github.com/dgrijalva/jwt-go"
)

func TestLoadKey(t *testing.T) {
	kl := new(mockKeyLoader)
	for _, test := range []struct {
		header    map[string]interface{}
		want      interface{}
		wantError error
	}{
		{map[string]interface{}{}, nil, ErrMissingKeyId},
		{map[string]interface{}{"kid": 42}, nil, ErrInvalidKeyId},
		{map[string]interface{}{"kid": "RS256"}, testRSAPKey, nil},
		{map[string]interface{}{"kid": "ES256"}, testECDSAPKey, nil},
	} {
		token := &jwt.Token{Header: test.header}
		k, err := loadKey(kl, token)

		if test.wantError != err {
			t.Errorf("Unexpected error status. Wanted %v, got %v", test.wantError, err)
		}

		if k != test.want {
			t.Errorf("Unexpected key loaded. Wanted %v, got %v", k, test.want)
		}
	}
}

func TestJwtValidator(t *testing.T) {
	kl := new(mockKeyLoader)
	kf := jwtValidator(kl)
	for _, test := range []struct {
		method    jwt.SigningMethod
		want      interface{}
		wantError bool
	}{
		{jwt.SigningMethodHS256, nil, true},
		{jwt.SigningMethodHS384, nil, true},
		{jwt.SigningMethodHS512, nil, true},
		{jwt.SigningMethodRS256, nil, false},
		{jwt.SigningMethodRS384, nil, false},
		{jwt.SigningMethodRS512, nil, false},
		{jwt.SigningMethodES256, nil, false},
		{jwt.SigningMethodES384, nil, false},
		{jwt.SigningMethodES512, nil, false},
	} {
		token := &jwt.Token{Method: test.method}
		k, err := kf(token)

		if test.wantError && err == nil {
			t.Error("Unexpected error status. Wanted error but didn't")
		}

		if k != test.want {
			t.Errorf("Unexpected key loaded. Wanted %v, got %v", k, test.want)
		}
	}
}
