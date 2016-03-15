package revoke

import (
	"encoding/json"
	"log"
	"time"
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
	Revs []jsonRevocation `json:"revocations"`
}

type jsonRevocation struct {
	Type      string `json:"type"` // TOKEN, CLAIM, GLOBAL
	RevokedAt int    `json:"revoked_at"`
	Data      struct {
		Name          string `json:"name,omitempty"`           // CLAIM
		ValueHash     string `json:"value_hash,omitempty"`     // CLAIM
		IssuedBefore  int    `json:"issued_before,omitempty"`  // CLAIM, GLOBAL
		TokenHash     string `json:"token_hash,omitempty"`     // TOKEN
		HashAlgorithm string `json:"hash_algorithm,omitempty"` // CLAIM, TOKEN
	} `json:"data"`
}

func (r *jsonRevoke) UnmarshallJSON(data []byte) (err error) {
	if err = json.Unmarshal(data, &r); err != nil {
		log.Println("Error unmarshalling revocation json. " + err.Error())
		return err
	}

	return
}

func (r *Revocation) getRevocationFromJson(j *jsonRevocation) {

	t := int(time.Now().Unix())

	r.Data = make(map[string]interface{})
	switch j.Type {
	case "TOKEN":
		valid := isHashTimestampValid(j.Data.TokenHash, j.RevokedAt)
		if !valid {
			log.Printf("Invalid revocation data (TOKEN). TokenHash: %s, RevokedAt: %d", j.Data.TokenHash, j.RevokedAt)
			return
		}
		r.Data["token_hash"] = j.Data.TokenHash
	case "CLAIM":
		valid := isHashTimestampValid(j.Data.ValueHash, j.Data.IssuedBefore, j.RevokedAt)
		if !valid {
			log.Printf("Invalid revocation data (CLAIM). ValueHash: %s, IssuedBefore: %d, RevokedAt: %d", j.Data.ValueHash, j.Data.IssuedBefore, j.RevokedAt)
			return
		}
		if j.Data.Name == "" {
			log.Println("Invalid revocation data (missing claim name).")
			return
		}
		r.Data["value_hash"] = j.Data.ValueHash
		r.Data["issued_before"] = j.Data.IssuedBefore
		r.Data["name"] = j.Data.Name
	case "GLOBAL":
		valid := isHashTimestampValid("thisStringDoesntMatter", j.Data.IssuedBefore, j.RevokedAt)
		if !valid {
			log.Printf("Invalid revocation data (GLOBAL). IssuedBefore: %d, RevokedAt: %d", j.Data.IssuedBefore, j.RevokedAt)
			return
		}
		if j.Data.IssuedBefore > t {
			log.Printf("Invalid revocation data (GLOBAL). IssuedBefore cannot be in the future. Now: %d, IssuedBefore: %s", t, j.Data.IssuedBefore)
			return
		}
		r.Data["issued_before"] = j.Data.IssuedBefore
	default:
		log.Printf("Unsupported revocation type: %s", j.Type)
		return
	}

	r.Data["revoked_at"] = j.RevokedAt
	r.Type = j.Type
	r.Timestamp = t
	return
}

func isHashTimestampValid(hash string, timestamp ...int) bool {
	if hash == "" {
		return false
	}

	for _, val := range timestamp {
		if val <= 0 {
			return false
		}
	}

	return true
}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
