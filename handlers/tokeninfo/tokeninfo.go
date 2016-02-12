package tokeninfo

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"time"
)

type TokenInfo struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	Uid          string   `json:"uid"`
	GrantType    string   `json:"grant_type"`
	OpenId       string   `json:"open_id"`
	Scope        []string `json:"scope"`
	Realm        string   `json:"realm"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int      `json:"expires_in"`
}

func buildScopes(s []interface{}) []string {
	scopes := make([]string, len(s))
	for i, scope := range s {
		scopes[i] = scope.(string)
	}
	return scopes
}

func buildTokenInfo(t *jwt.Token) (*TokenInfo, error) {
	scope := buildScopes(t.Claims["scope"].([]interface{}))
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
	ts, ok := t.Claims["exp"].(float64)
	if !ok {
		return 0
	}
	return int(time.Unix(int64(ts), 0).Sub(time.Now()).Seconds())
}
