package tokeninfo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
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

const OPENID_PROVIDER_CONFIGURATION_URL = "OPENID_PROVIDER_CONFIGURATION_URL"

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

var publicKeys map[string]interface{} = map[string]interface{}{}

func fetchKey(kid string) (interface{}, error) {

	// http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
	// https://planb-provider.example.org/.well-known/openid-configuration
	url := os.Getenv(OPENID_PROVIDER_CONFIGURATION_URL)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	config := make(map[string]interface{})
	if err = json.Unmarshal(body, &config); err != nil {
		return nil, err
	}
	uri, ok := config["jwks_uri"].(string)
	if !ok {
		return nil, fmt.Errorf("Invalid OpenID Configuration: Invalid 'jwks_uri'")
	}

	// Example: https://www.googleapis.com/oauth2/v3/certs
	resp2, err2 := http.Get(uri)
	if err2 != nil {
		return nil, err2
	}
	defer resp2.Body.Close()
	body, err = ioutil.ReadAll(resp2.Body)
	certs := make(map[string]interface{})
	if err = json.Unmarshal(body, &certs); err != nil {
		return nil, err
	}
	m, has := certs["keys"]
	if !has {
		return nil, fmt.Errorf("Missing keys")
	}

	keys, ok := m.([]interface{})
	if !ok {
		return nil, fmt.Errorf("Invalid keys map")
	}

	for _, k := range keys {
		km, ok := k.(map[string]interface{})
		if !ok {
			return nil, errors.New("Invalid key map")
		}
		if km["kid"].(string) == kid {
			return buildKey(km)
		}
	}

	return nil, fmt.Errorf("Key '%s' not found", kid)
}

func buildKey(k map[string]interface{}) (interface{}, error) {
	if k["alg"].(string) != "ES256" {
		return nil, fmt.Errorf("Unsupported algorithm '%s'", k["alg"].(string))
	}

	xbuf, err := base64.RawURLEncoding.DecodeString(k["x"].(string))
	if err != nil {
		return nil, fmt.Errorf("Invalid ECDSA coordinate X")
	}
	ybuf, err := base64.RawURLEncoding.DecodeString(k["y"].(string))
	if err != nil {
		return nil, fmt.Errorf("Invalid ECDSA coordinate Y")
	}

	x := new(big.Int).SetBytes(xbuf)
	y := new(big.Int).SetBytes(ybuf)

	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func loadKey(t *jwt.Token) (interface{}, error) {
	kid, ok := t.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("Missing key ID")
	}
	key, has := publicKeys[kid]
	if !has {
		k, err := fetchKey(kid)
		if err != nil {
			return nil, err
		}
		// TODO: synchronize for concurrency or whatever
		publicKeys[kid] = k
		return k, nil
	}

	return key, nil
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
