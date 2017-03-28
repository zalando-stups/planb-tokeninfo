package jwthandler

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/zalando/planb-tokeninfo/options"
	"github.com/zalando/planb-tokeninfo/processor"
)

func TestTokenInfo(t *testing.T) {
	for _, test := range []struct {
		token     jwt.Token
		want      *processor.TokenInfo
		wantError bool
	}{
		{jwt.Token{}, nil, true},
		{jwt.Token{Claims: jwt.MapClaims{"scope": "uid"}}, nil, true},
		{jwt.Token{Claims: jwt.MapClaims{"scope": []interface{}{"uid"}}}, nil, true},
		{jwt.Token{Claims: jwt.MapClaims{"scope": []interface{}{"uid"}, "sub": 42}}, nil, true},
		{jwt.Token{Claims: jwt.MapClaims{"scope": []interface{}{"uid"}, "sub": "foo"}}, nil, true},
		{jwt.Token{Claims: jwt.MapClaims{"scope": []interface{}{"uid"}, "sub": "foo", "realm": "/test"}}, nil, true},
		{jwt.Token{Claims: jwt.MapClaims{"scope": []interface{}{}, "sub": "foo", "realm": "/test", "azp": 123}}, nil, true},
		{
			jwt.Token{Claims: jwt.MapClaims{
				"scope": []interface{}{"uid"},
				"sub":   "foo",
				"realm": "/test",
				"exp":   "invalid-number"}},
			nil,
			true},
		{
			jwt.Token{Claims: jwt.MapClaims{
				"scope": []interface{}{"uid"},
				"sub":   "foo",
				"realm": "/test",
				"exp":   []byte("1")}},
			nil,
			true},
		{
			jwt.Token{Claims: jwt.MapClaims{
				"scope": []interface{}{"uid"},
				"sub":   "foo",
				"realm": "/test",
				"exp":   float64(43)}},
			&processor.TokenInfo{
				GrantType: "password",
				TokenType: "Bearer",
				Scope:     []string{"uid"},
				UID:       "foo",
				Realm:     "/test",
				ExpiresIn: 1},
			false},
		{
			jwt.Token{Claims: jwt.MapClaims{
				"scope": []interface{}{},
				"sub":   "foo",
				"realm": "/test",
				"azp":   "myclient-123",
				"exp":   float64(43)}},
			&processor.TokenInfo{
				GrantType: "password",
				TokenType: "Bearer",
				Scope:     []string{},
				UID:       "foo",
				Realm:     "/test",
				ClientId:  "myclient-123",
				ExpiresIn: 1},
			false},
	} {
		ti, err := NewTokenInfo(&test.token, time.Unix(42, 0))

		if test.wantError && err == nil {
			t.Error("Wanted an error but got none")
		}

		if !reflect.DeepEqual(ti, test.want) {
			t.Errorf("Unexpected token info. Wanted %v, got %v", test.want, ti)
		}
	}
}

type TestJWTProcessor struct {
}

func (jwtProcessor TestJWTProcessor) Process(t *jwt.Token, timeBase time.Time) (*processor.TokenInfo, error) {
	return &processor.TokenInfo{
		AccessToken: t.Raw,
		UID:         "uid",
		GrantType:   "mygrant",
		Scope:       []string{},
		Realm:       "/test",
		ClientId:    "client",
		TokenType:   "Bearer",
		ExpiresIn:   42,
	}, nil
}

func TestJwtProcessor(t *testing.T) {
	options.AppSettings.JwtProcessors["test-processor"] = TestJWTProcessor{}
	for _, test := range []struct {
		token     jwt.Token
		want      *processor.TokenInfo
		wantError bool
	}{
		{
			jwt.Token{Claims: jwt.MapClaims{"iss": "test-processor"}},
			&processor.TokenInfo{
				GrantType: "mygrant",
				TokenType: "Bearer",
				Scope:     []string{},
				UID:       "uid",
				Realm:     "/test",
				ClientId:  "client",
				ExpiresIn: 42},
			false},
	} {
		ti, err := NewTokenInfo(&test.token, time.Unix(42, 0))

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
		token *processor.TokenInfo
		want  string
	}{
		{&processor.TokenInfo{},
			"{\"access_token\":\"\",\"expires_in\":0,\"grant_type\":\"\",\"realm\":\"\",\"scope\":null,\"token_type\":\"\",\"uid\":\"\"}\n"},
		{&processor.TokenInfo{RefreshToken: "foo"},
			"{\"access_token\":\"\",\"expires_in\":0,\"grant_type\":\"\",\"realm\":\"\",\"refresh_token\":\"foo\",\"scope\":null,\"token_type\":\"\",\"uid\":\"\"}\n"},
		{&processor.TokenInfo{ClientId: "client-123"},
			"{\"access_token\":\"\",\"client_id\":\"client-123\",\"expires_in\":0,\"grant_type\":\"\",\"realm\":\"\",\"scope\":null,\"token_type\":\"\",\"uid\":\"\"}\n"},
		{&processor.TokenInfo{
			GrantType: "password",
			TokenType: "Bearer",
			Scope:     []string{"uid", "foo", "bar"},
			UID:       "foo",
			Realm:     "/test",
			ExpiresIn: 1},
			"{\"access_token\":\"\",\"bar\":true,\"expires_in\":1,\"foo\":true,\"grant_type\":\"password\",\"realm\":\"/test\",\"scope\":[\"uid\",\"foo\",\"bar\"],\"token_type\":\"Bearer\",\"uid\":\"foo\"}\n"},
		{&processor.TokenInfo{
			PrivateClaims: map[string]string{"foo": "bar"}},
			"{\"access_token\":\"\",\"expires_in\":0,\"foo\":\"bar\",\"grant_type\":\"\",\"realm\":\"\",\"scope\":null,\"token_type\":\"\",\"uid\":\"\"}\n"},
	} {
		buf := new(bytes.Buffer)
		Marshal(test.token, buf)
		s := buf.String()
		if s != test.want {
			t.Errorf("Unexpected serialization. Wanted %v, got %v", test.want, s)
		}
	}
}
