package jwthandler

import (
	"testing"
	"github.com/dgrijalva/jwt-go"
	"reflect"
)

func TestTokenInfo(t *testing.T) {
	for _, test := range []struct {
		token jwt.Token
		want *TokenInfo
		wantError bool
	}{
		{jwt.Token{}, nil, true},
		{jwt.Token{Claims: map[string]interface{}{"scope": "uid"}}, nil, true},
		{jwt.Token{Claims: map[string]interface{}{"scope": "uid", "sub": "foo"}}, nil, true},
	} {
		ti, err := newTokenInfo(&test.token)

		if test.wantError && err == nil {
			t.Error("Wanted an error but got none")
		}

		if !reflect.DeepEqual(ti, test.want) {
			t.Errorf("Unexpected token info. Wanted %v, got %v", test.want, ti)
		}
	}
}