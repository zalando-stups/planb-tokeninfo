package jwthandler

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/zalando/planb-tokeninfo/options"
	"github.com/zalando/planb-tokeninfo/processor"
)

const (
	JwtClaimScope  = "scope"
	JwtClaimSub    = "sub"
	JwtClaimRealm  = "realm"
	JwtClaimAzp    = "azp"
	JwtClaimExp    = "exp"
	JwtClaimIssuer = "iss"
)

var (
	// ErrInvalidClaimScope should be used whenever the scope claim is invalid or missing in the JWT
	ErrInvalidClaimScope = errors.New("Invalid claim: scope")
	// ErrInvalidClaimRealm should be used whenever the scope realm is invalid or missing in the JWT
	ErrInvalidClaimRealm = errors.New("Invalid claim: realm")
	// ErrInvalidClaimSub should be used whenever the claim sub is invalid or missing in the JWT
	ErrInvalidClaimSub = errors.New("Invalid claim: sub")
	// ErrInvalidClaimAzp should be used whenever the claim azp is invalid or missing in the JWT
	ErrInvalidClaimAzp = errors.New("Invalid claim: azp")
	// ErrInvalidClaimExp should be used whenever the claim exp is invalid or missing in the JWT
	ErrInvalidClaimExp = errors.New("Invalid claim: exp")
)

func Marshal(ti *processor.TokenInfo, w io.Writer) error {
	m := make(map[string]interface{})
	m["access_token"] = ti.AccessToken
	if ti.RefreshToken != "" {
		m["refresh_token"] = ti.RefreshToken
	}
	m["uid"] = ti.UID
	m["grant_type"] = ti.GrantType
	m["scope"] = ti.Scope
	m["realm"] = ti.Realm
	m["token_type"] = ti.TokenType
	m["expires_in"] = ti.ExpiresIn

	if ti.Scope != nil {
		// compatibility: add "truthy" attributes to Token Info response for all existing scopes
		// https://github.com/zalando/planb-tokeninfo/issues/29
		for _, scope := range ti.Scope {
			_, exists := m[scope]
			if !exists {
				m[scope] = true
			}
		}
	}

	if ti.ClientId != "" {
		m["client_id"] = ti.ClientId
	}

	for k, v := range ti.PrivateClaims {
		m[k] = v
	}

	return json.NewEncoder(w).Encode(m)
}

func defaultNewTokenInfo(t *jwt.Token, timeBase time.Time) (*processor.TokenInfo, error) {
	scopes, ok := ClaimAsStrings(t, JwtClaimScope)
	if !ok {
		return nil, ErrInvalidClaimScope
	}

	sub, ok := ClaimAsString(t, JwtClaimSub)
	if !ok {
		return nil, ErrInvalidClaimSub
	}

	realm, ok := ClaimAsString(t, JwtClaimRealm)
	if !ok {
		return nil, ErrInvalidClaimRealm
	}

	clientId := ""
	if claims, ok := t.Claims.(jwt.MapClaims); ok {
		_, has := claims[JwtClaimAzp]
		if has {
			clientId, ok = ClaimAsString(t, JwtClaimAzp)
			if !ok {
				return nil, ErrInvalidClaimAzp
			}
		}
	}

	exp, ok := ClaimAsInt64(t, JwtClaimExp)
	if !ok {
		return nil, ErrInvalidClaimExp
	}

	expiresIn := int(time.Unix(exp, 0).Sub(timeBase).Seconds())

	return &processor.TokenInfo{
		AccessToken: t.Raw,
		UID:         sub,
		GrantType:   "password",
		Scope:       scopes,
		Realm:       realm,
		ClientId:    clientId,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
	}, nil
}

func NewTokenInfo(t *jwt.Token, timeBase time.Time) (*processor.TokenInfo, error) {
	issuer, ok := ClaimAsString(t, JwtClaimIssuer)
	if ok {
		jwtprocessor, found := options.AppSettings.JwtProcessors[issuer]
		if found {
			return jwtprocessor.Process(t, timeBase)
		}
	}
	return defaultNewTokenInfo(t, timeBase)
}

func ClaimAsStrings(t *jwt.Token, claim string) ([]string, bool) {
	if c, ok := getClaim(t, claim); ok {
		value, ok := c.([]interface{})
		if !ok {
			log.Printf("Invalid string array value for claim %q = %v", claim, c)
			return nil, false
		}
		result := make([]string, len(value))
		for i, scope := range value {
			result[i] = scope.(string)
		}
		return result, true
	}
	return nil, false
}

func ClaimAsString(t *jwt.Token, claim string) (string, bool) {
	if c, ok := getClaim(t, claim); ok {
		value, ok := c.(string)
		if !ok {
			log.Printf("Invalid string value for claim %q = %v", claim, c)
			return "", false
		}
		return value, true
	}
	return "", false
}

func ClaimAsInt64(t *jwt.Token, claim string) (int64, bool) {
	c, ok := getClaim(t, claim)
	if !ok {
		return 0, false
	}
	switch c.(type) {
	case float64:
		return int64(c.(float64)), true
	default:
		log.Printf("Invalid number format for claim %q = %v", claim, c)
	}
	return 0, false
}

func getClaim(t *jwt.Token, claim string) (interface{}, bool) {
	if claims, ok := t.Claims.(jwt.MapClaims); ok {
		c, has := claims[claim]
		if !has {
			return "", false
		}
		return c, true
	}
	return "", false
}

func maskToken(rawToken string) string {
	indexOfSignature := strings.LastIndex(rawToken, ".")
	if indexOfSignature > -1 {
		// return signature of JWT as masked token
		return rawToken[indexOfSignature:]
	}
	return ""
}
