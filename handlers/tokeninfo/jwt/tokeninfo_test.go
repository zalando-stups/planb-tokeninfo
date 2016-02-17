package jwthandler

import (
	"reflect"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func TestTokenInfo(t *testing.T) {
	for _, test := range []struct {
		token     jwt.Token
		want      *TokenInfo
		wantError bool
	}{
		{jwt.Token{}, nil, true},
		{jwt.Token{Claims: map[string]interface{}{"scope": "uid"}}, nil, true},
		{jwt.Token{Claims: map[string]interface{}{"scope": []interface{}{"uid"}}}, nil, true},
		{jwt.Token{Claims: map[string]interface{}{"scope": []interface{}{"uid"}, "sub": 42}}, nil, true},
		{jwt.Token{Claims: map[string]interface{}{"scope": []interface{}{"uid"}, "sub": "foo"}}, nil, true},
		{jwt.Token{Claims: map[string]interface{}{"scope": []interface{}{"uid"}, "sub": "foo", "realm": "/test"}}, nil, true},
		{
			jwt.Token{Claims: map[string]interface{}{
				"scope": []interface{}{"uid"},
				"sub":   "foo",
				"realm": "/test",
				"exp":   "invalid-number"}},
			nil,
			true},
		{
			jwt.Token{Claims: map[string]interface{}{
				"scope": []interface{}{"uid"},
				"sub":   "foo",
				"realm": "/test",
				"exp":   []byte("1")}},
			nil,
			true},
		{
			jwt.Token{Claims: map[string]interface{}{
				"scope": []interface{}{"uid"},
				"sub":   "foo",
				"realm": "/test",
				"exp":   float64(43)}},
			&TokenInfo{
				GrantType: "password",
				TokenType: "Bearer",
				Scope:     []string{"uid"},
				Uid:       "foo",
				Realm:     "/test",
				ExpiresIn: 1},
			false},
	} {
		ti, err := newTokenInfo(&test.token, time.Unix(42, 0))

		if test.wantError && err == nil {
			t.Error("Wanted an error but got none")
		}

		if !reflect.DeepEqual(ti, test.want) {
			t.Errorf("Unexpected token info. Wanted %v, got %v", test.want, ti)
		}
	}
}
