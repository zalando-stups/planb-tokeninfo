package jwthandler

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	jwtClaimScope = "scope"
	jwtClaimSub   = "sub"
	jwtClaimRealm = "realm"
	jwtClaimAzp   = "azp"
	jwtClaimExp   = "exp"
)

var (
	// ErrInvalidClaimScope should be used whenever the scope claim is invalid or missing in the JWT
	ErrInvalidClaimScope = errors.New("Invalid claim: scope")
	// ErrInvalidClaimSub should be used whenever the scope sub is invalid or missing in the JWT
	ErrInvalidClaimSub = errors.New("Invalid claim: sub")
	// ErrInvalidClaimRealm should be used whenever the scope realm is invalid or missing in the JWT
	ErrInvalidClaimRealm = errors.New("Invalid claim: realm")
	ErrInvalidClaimAzp   = errors.New("Invalid claim: azp")
	// ErrInvalidClaimExp should be used whenever the scope exp is invalid or missing in the JWT
	ErrInvalidClaimExp = errors.New("Invalid claim: exp")
)

// TokenInfo type is used to serialize a JWT validation result in a standard Token Info JSON format
type TokenInfo struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	UID          string   `json:"uid"`
	GrantType    string   `json:"grant_type"`
	OpenID       string   `json:"open_id"`
	Scope        []string `json:"scope"`
	Realm        string   `json:"realm"`
	ClientId     string   `json:"client_id"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int      `json:"expires_in"`
}

func (ti *TokenInfo) Marshal(w io.Writer) error {
	m := make(map[string]interface{})
	m["access_token"] = ti.AccessToken
	if ti.RefreshToken != "" {
		m["refresh_token"] = ti.RefreshToken
	}
	m["uid"] = ti.UID
	m["grant_type"] = ti.GrantType
	m["open_id"] = ti.OpenID
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

	return json.NewEncoder(w).Encode(m)
}

func newTokenInfo(t *jwt.Token, timeBase time.Time) (*TokenInfo, error) {
	scopes, ok := claimAsStrings(t, jwtClaimScope)
	if !ok {
		return nil, ErrInvalidClaimScope
	}

	sub, ok := claimAsString(t, jwtClaimSub)
	if !ok {
		return nil, ErrInvalidClaimSub
	}

	realm, ok := claimAsString(t, jwtClaimRealm)
	if !ok {
		return nil, ErrInvalidClaimRealm
	}

	clientId := ""
	if claims, ok := t.Claims.(jwt.MapClaims); ok {
		_, has := claims[jwtClaimAzp]
		if has {
			clientId, ok = claimAsString(t, jwtClaimAzp)
			if !ok {
				return nil, ErrInvalidClaimAzp
			}
		}
	}

	exp, ok := claimAsInt64(t, jwtClaimExp)
	if !ok {
		return nil, ErrInvalidClaimExp
	}

	expiresIn := int(time.Unix(exp, 0).Sub(timeBase).Seconds())

	return &TokenInfo{
		AccessToken: t.Raw,
		UID:         sub,
		GrantType:   "password",
		OpenID:      t.Raw,
		Scope:       scopes,
		Realm:       realm,
		ClientId:    clientId,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
	}, nil
}

func claimAsStrings(t *jwt.Token, claim string) ([]string, bool) {
	if c, ok := getClaim(t, claim); ok {
		value, ok := c.([]interface{})
		if !ok {
			log.Printf("Invalid string array value for claim %q = %v", claim, c)
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
			log.Printf("Invalid string value for claim %q = %v", claim, c)
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
	default:
		log.Printf("Invalid number format for claim %q = %v", claim, c)
	}
	return 0, false
}

func getClaim(t *jwt.Token, claim string) (interface{}, bool) {
	if claims, ok := t.Claims.(jwt.MapClaims); ok {
		c, has := claims[claim]
		if !has {
			log.Printf("Missing claim %q for token %v", claim, t.Raw)
			return "", false
		}
		return c, true
	}
	log.Printf("Missing claim %q for token %v", claim, t.Raw)
	return "", false
}
