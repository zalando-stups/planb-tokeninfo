package main

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"net/http"
	"time"
)

/*

 {
  "links": [
    {
      "rel": "self",
      "href": "https://tusk-api-integration.greendale-staging.zalan.do/api/tokens/1ec91d60-b38d-4139-be88-de517c86ca0c"
    }
  ],
  "access_token": "1ec91d60-b38d-4139-be88-de517c86ca0c",
  "refresh_token": "2ecae60-c49e-3028-b133-d3547c86cb0c",
  "uid": "2342334",
  "grant_type": "password",
  "openid": "",
  "scope": [
    "uid",
    "openid"
  ],
  "realm": "/customers",
  "token_type": "Bearer",
  "expires_in": 2599
}
*/
type TokenInfo struct {
	AccessToken  string
	RefreshToken string
	Uid          string
	GrantType    string
	OpenId       string
	Scope        []string
	Realm        string
	TokenType    string
	ExpiresIn    int
}

func validateToken(req *http.Request) (*TokenInfo, error) {
	token, err := jwt.ParseFromRequest(req, func(token *jwt.Token) (interface{}, error) {
		var isrsa, isecdsa bool

		_, isrsa = token.Method.(*jwt.SigningMethodRSA)
		if !isrsa {
			_, isecdsa = token.Method.(*jwt.SigningMethodECDSA)
		}

		if !(isrsa || isecdsa) {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return loadKey(token)
	})

	if err == nil && token.Valid {
		return buildTokenInfo(token)
	} else {
		return nil, err
	}
}

func loadKey(t *jwt.Token) (interface{}, error) {
	key, err := ioutil.ReadFile("sample_key.pub")
	if err != nil {
		return nil, err
	}
	return key, nil
}

func buildTokenInfo(t *jwt.Token) (*TokenInfo, error) {
	scope, ok := t.Claims["scope"].([]string)
	if !ok {
		return nil, fmt.Errorf("Invalid scope claim %v", t.Claims["scope"])
	}
	sub, ok := t.Claims["sub"].(string)
	if !ok {
		return nil, fmt.Errorf("Invalid sub claim %v", t.Claims["sub"])
	}
	realm, ok := t.Claims["realm"].(string)
	if !ok {
		return nil, fmt.Errorf("Invalid realm claim %v", t.Claims["realm"])
	}

	return &TokenInfo{
		AccessToken: t.Raw,
		Uid:         sub,
		GrantType:   "password",
		OpenId:      t.Raw,
		Scope:       scope,
		Realm:       realm,
		TokenType:   "Bearer",
		ExpiresIn:   calculateExpiration(t),
	}, nil
}

func calculateExpiration(t *jwt.Token) int {
	ts, ok := t.Claims["exp"].(int64)
	if !ok {
		return 0
	}
	return int(time.Unix(ts, 0).Sub(time.Now()).Seconds())
}
