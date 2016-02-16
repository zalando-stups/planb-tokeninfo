package revoke

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

// TODO: do we want to keep a history of 'Global' revocations?
type Revocation struct {
	Claims map[string]map[string]int // claim name mapped to a hash mapped to issued before
	Tokens map[string]int            // token hash mapped to revoked at
	Global int                       // issued before
}

// TODO: would it be better to store like this for the cache?
/*
type Revoke struct {
	Type      string // token, claim, global
	Name	  string // claim
	Hash      string // token, claim
	Timestamp int    // token claim global
}
*/

type jsonRevoke struct {
	Meta struct {
		ForceRefresh string `json:"force_refresh"`
	} `json:"meta"`
	Revocation []struct {
		Type      string `json:"type"` // TOKEN, CLAIM, GLOBAL
		RevokedAt string `json:"revoked_at"`
		Data      struct {
			Name         string `json:"name,omitempty"`          // CLAIM
			ValueHash    string `json:"value_hash,omitempty"`    // CLAIM
			IssuedBefore string `json:"issued_before,omitempty"` // CLAIM, GLOBAL
			TokenHash    string `json:"token_hash,omitempty"`    // TOKEN
			RevokedAt    string `json:"revoked_at,omitempty"`    // TOKEN
		} `json:"data"`
	} `json:"revocations"`
}

func (r *jsonRevoke) UnmarshallJSON(data []byte) (err error) {
	var buf jsonRevoke
	if err = json.Unmarshall(data, &buf); err != nil {
		log.Errorf("Error unmarshalling revocation json. " + err.Error())
		return err
	}

	// TODO: if we force refresh to a previous time, we'll probably get the
	// force refresh json again and end up in an infinite loop of refreshing.
	if buf.ForceRefresh != "" {
		i, err := strconv.Atoi(buf.ForceRefresh)
		if err != nil {
			log.Errorf("Error converting ForceRefresh to int." + err.Error())
		} else {
			refreshCacheFromTime(i)
		}
	}

	return
}

func (r *Revocation) getRevocationFromJson(json *jsonRevoke.Revocation) {

	for j := range json {

		switch j.Type {
		case "TOKEN":
			valid, i := isHashTimestampValid(j.Data.TokenHash, j.Data.RevokedAt)
			if !valid {
				log.Errorf("Invalid revocation data. TokenHash: %s, RevokedAt: %s", j.Data.TokenHash, j.Data.RevokedAt)
				continue
			}
			r.Tokens[j.Data.TokenHash] = i
		case "CLAIM":
			valid, i := isHashTimestampValid(j.Data.ValueHash, j.Data.IssuedBefore)
			if !valid {
				log.Errorf("Invalid revocation data. ValueHash: %s, IssuedBefore: %s", j.Data.ValueHash, j.Data.IssuedBefore)
				continue
			}
			r.Claims[j.Data.Name][j.Data.ValueHash] = i
		case "GLOBAL":
			i, err := strconv.Atoi(j.Data.IssuedBefore)
			if err != nil {
				log.Errorf("Erorr converting IssuedBefore to int. " + err.Error())
				continue
			}
			r.Gobal = i
		default:
			log.Errorf("Unsupported revocation type: %s", j.Type)
		}

	}
	return
}

func isHashTimestampValid(hash, timestamp string) (bool, int) {
	if hash == "" || timestamp == "" {
		return false, -1
	}

	i, err := strconv.Atoi(timestamp)
	if err != nil {
		log.Errorf("Erorr converting timestamp to int. " + err.Error())
		return false, -1
	}

	return true, i

}
