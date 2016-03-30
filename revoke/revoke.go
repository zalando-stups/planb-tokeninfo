package revoke

import (
	"errors"
	"log"
	"strings"
	"time"
)

var (
	REVOCATION_TYPE_TOKEN        = "TOKEN"
	REVOCATION_TYPE_CLAIM        = "CLAIM"
	REVOCATION_TYPE_GLOBAL       = "GLOBAL"
	REVOCATION_TYPE_FORCEREFRESH = "FORCEREFRESH"

	ErrInvalidRevocation = errors.New("Invalid Revocation data")
	ErrIssuedInFuture    = errors.New("Issued in the future")
	ErrUnsupportedType   = errors.New("Unsupported revocation type")
	ErrMissingClaimName  = errors.New("Missing claim name")
)

type Revocation struct {
	Type      string // token, claim, global
	Data      map[string]interface{}
	Timestamp int
}

type jsonRevoke struct {
	Meta struct {
		RefreshFrom      int `json:"REFRESH_FROM"`
		RefreshTimestamp int `json:"REFRESH_TIMESTAMP"`
	} `json:"meta"`
	Revs []*jsonRevocation `json:"revocations"`
}

type jsonRevocation struct {
	Type      string `json:"type"` // TOKEN, CLAIM, GLOBAL
	RevokedAt int    `json:"revoked_at"`
	Data      struct {
		Names         []string `json:"names,omitempty"`          // CLAIM
		ValueHash     string   `json:"value_hash,omitempty"`     // CLAIM
		IssuedBefore  int      `json:"issued_before,omitempty"`  // CLAIM, GLOBAL
		TokenHash     string   `json:"token_hash,omitempty"`     // TOKEN
		HashAlgorithm string   `json:"hash_algorithm,omitempty"` // CLAIM, TOKEN
	} `json:"data"`
}

func (j *jsonRevocation) validToken() bool {
	if j.Type == REVOCATION_TYPE_TOKEN &&
		j.RevokedAt != 0 &&
		j.Data.TokenHash != "" {
		return true
	}
	return false
}

func (j *jsonRevocation) validClaim() bool {
	if j.Type == REVOCATION_TYPE_CLAIM &&
		j.RevokedAt != 0 &&
		j.Data.ValueHash != "" &&
		j.Data.IssuedBefore != 0 {
		return true
	}
	return false
}

func (j *jsonRevocation) validGlobal() bool {
	if j.Type == REVOCATION_TYPE_GLOBAL &&
		j.RevokedAt != 0 &&
		j.Data.IssuedBefore != 0 {
		return true
	}
	return false
}

func getRevocationFromJson(j *jsonRevocation) (*Revocation, error) {

	r := &Revocation{}
	t := int(time.Now().Unix())

	r.Data = make(map[string]interface{})
	switch j.Type {
	case REVOCATION_TYPE_TOKEN:
		if !j.validToken() {
			log.Printf("Invalid revocation data (TOKEN). TokenHash: %s, RevokedAt: %d", j.Data.TokenHash, j.RevokedAt)
			return nil, ErrInvalidRevocation
		}
		r.Data["token_hash"] = j.Data.TokenHash

	case REVOCATION_TYPE_CLAIM:
		if !j.validClaim() {
			log.Printf("Invalid revocation data (CLAIM). ValueHash: %s, IssuedBefore: %d, RevokedAt: %d", j.Data.ValueHash, j.Data.IssuedBefore, j.RevokedAt)
			return nil, ErrInvalidRevocation
		}
		if len(j.Data.Names) == 0 {
			log.Println("Invalid revocation data (missing claim name).")
			return nil, ErrMissingClaimName
		}
		r.Data["value_hash"] = j.Data.ValueHash
		r.Data["issued_before"] = j.Data.IssuedBefore
		r.Data["names"] = strings.Join(j.Data.Names, "|")

	case REVOCATION_TYPE_GLOBAL:
		if !j.validGlobal() {
			log.Printf("Invalid revocation data (GLOBAL). IssuedBefore: %d, RevokedAt: %d", j.Data.IssuedBefore, j.RevokedAt)
			return nil, ErrInvalidRevocation
		}
		if j.Data.IssuedBefore > t {
			log.Printf("Invalid revocation data (GLOBAL). IssuedBefore cannot be in the future. Now: %d, IssuedBefore: %s", t, j.Data.IssuedBefore)
			return nil, ErrIssuedInFuture
		}
		r.Data["issued_before"] = j.Data.IssuedBefore
	default:
		log.Printf("Unsupported revocation type: %s", j.Type)
		return nil, ErrUnsupportedType
	}

	r.Data["revoked_at"] = j.RevokedAt
	r.Type = j.Type
	r.Timestamp = t
	return r, nil
}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
