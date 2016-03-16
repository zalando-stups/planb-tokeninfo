package jwthandler

import (
	"bytes"
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
				UID:       "foo",
				Realm:     "/test",
				ExpiresIn: 1},
			false},
		{
			jwt.Token{Claims: map[string]interface{}{
				"scope": []interface{}{},
				"sub":   "foo",
				"realm": "/test",
				"azp":   "myclient-123",
				"exp":   float64(43)}},
			&TokenInfo{
				GrantType: "password",
				TokenType: "Bearer",
				Scope:     []string{},
				UID:       "foo",
				Realm:     "/test",
				ClientId:  "myclient-123",
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

func TestMarshal(t *testing.T) {

	for _, test := range []struct {
		token *TokenInfo
		want  string
	}{
		{&TokenInfo{},
			"{\"access_token\":\"\",\"expires_in\":0,\"grant_type\":\"\",\"open_id\":\"\",\"realm\":\"\",\"scope\":null,\"token_type\":\"\",\"uid\":\"\"}\n"},
		{&TokenInfo{RefreshToken: "foo"},
			"{\"access_token\":\"\",\"expires_in\":0,\"grant_type\":\"\",\"open_id\":\"\",\"realm\":\"\",\"refresh_token\":\"foo\",\"scope\":null,\"token_type\":\"\",\"uid\":\"\"}\n"},
		{&TokenInfo{
			GrantType: "password",
			TokenType: "Bearer",
			Scope:     []string{"uid", "foo", "bar"},
			UID:       "foo",
			Realm:     "/test",
			ExpiresIn: 1},
			"{\"access_token\":\"\",\"bar\":true,\"expires_in\":1,\"foo\":true,\"grant_type\":\"password\",\"open_id\":\"\",\"realm\":\"/test\",\"scope\":[\"uid\",\"foo\",\"bar\"],\"token_type\":\"Bearer\",\"uid\":\"foo\"}\n"},
	} {
		buf := new(bytes.Buffer)
		test.token.Marshal(buf)
		s := buf.String()
		if s != test.want {
			t.Errorf("Unexpected serialization. Wanted %v, got %v", test.want, s)
		}
	}
}
