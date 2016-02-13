package jwthandler

import (
	"github.com/dgrijalva/jwt-go"
	"time"
	"github.com/coreos/dex/pkg/log"
	"errors"
	"strconv"
)

const (
	JWT_CLAIM_SCOPE = "scope"
	JWT_CLAIM_SUB = "sub"
	JWT_CLAIM_REALM = "realm"
	JWT_CLAIM_EXP = "exp"
)

var (
	ErrInvalidClaimScope = errors.New("Invalid claim: scope")
	ErrInvalidClaimSub = errors.New("Invalid claim: sub")
	ErrInvalidClaimRealm = errors.New("Invalid claim: realm")
	ErrInvalidClaimExp = errors.New("Invalid claim: exp")
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

func newTokenInfo(t *jwt.Token) (*TokenInfo, error) {
	scopes, ok := claimAsStrings(t, JWT_CLAIM_SCOPE)
	if !ok {
		return nil, ErrInvalidClaimScope
	}

	sub, ok := claimAsString(t, JWT_CLAIM_SUB)
	if !ok {
		return nil, ErrInvalidClaimSub
	}

	realm, ok := claimAsString(t, JWT_CLAIM_REALM)
	if !ok {
		return nil, ErrInvalidClaimRealm
	}

	exp, ok := claimAsInt64(t, JWT_CLAIM_EXP)
	if !ok {
		return nil, ErrInvalidClaimExp
	}

	expiresIn := int(time.Unix(exp, 0).Sub(time.Now()).Seconds())

	return &TokenInfo{
		AccessToken: t.Raw,
		Uid:         sub,
		GrantType:   "password",
		OpenId:      t.Raw,
		Scope:       scopes,
		Realm:       realm,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
	}, nil
}

func claimAsStrings(t *jwt.Token, claim string) ([]string, bool) {
	if c, ok := getClaim(t, claim); ok {
		value, ok := c.([]interface{})
		if !ok {
			log.Debugf("Invalid string array value for claim %q = %v", claim, c)
			return nil, false
		}
		strings := make([]string, len(value))
		for i, scope := range value {
			strings[i] = scope.(string)
		}
		return strings, true
	}
	return nil, false
}

func claimAsString(t *jwt.Token, claim string) (string, bool) {
	if c, ok := getClaim(t, claim); ok {
		value, ok := c.(string)
		if !ok {
			log.Debugf("Invalid string value for claim %q = %v", claim, c)
			return "", false
		}
		return value, true
	}
	return "", false
}

func claimAsInt64(t *jwt.Token, claim string) (int64, bool) {
	c, ok := getClaim(t, claim)
	if !ok {
		return 0, false
	}
	switch c.(type) {
	case float64:
		return int64(c.(float64)), true
	case string:
		res, err := strconv.ParseInt(c.(string), 10, 64)
		if err != nil {
			log.Error(err)
			break
		}
		return res, true
	default:
		log.Debugf("Invalid number format for claim %q = %v", claim, c)
	}
	return 0, false
}

func getClaim(t *jwt.Token, claim string) (interface{}, bool) {
	c, has := t.Claims[claim]
	if !has {
		log.Debugf("Missing claim %q for token %v", claim, t.Raw)
		return "", false
	}
	return c, true
}