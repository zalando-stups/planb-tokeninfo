package revoke

import (
	"encoding/json"
	"errors"
	"strconv"
	"time"
)

// TODO: do we want to keep a history of 'Global' revocations?
type Revocation struct {
	Claims map[string]int // claim hash mapped to issued before
	Tokens map[string]int // token hash mapped to revoked at
	Global int            // issued before
}

type jsonRevoke struct {
	Meta struct {
		ForceRefresh string `json:"force_refresh"`
	} `json:"meta"`
	Revocations []struct {
		Properties string `json:"properties"` // TOKEN, CLAIM, GLOBAL
		RevokedAt  string `json:"revoked_at"`
		Data       struct {
			Properties   string `json:"properties,omitempty"`    // CLAIM
			ValueHash    string `json:"value_hash,omitempty"`    // CLAIM
			IssuedBefore string `json:"issued_before,omitempty"` // CLAIM, GLOBAL
			TokenHash    string `json:"token_hash,omitempty"`    // TOKEN
			RevokedAt    string `json:"revoked_at,omitempty"`    // TOKEN
		} `json:"data"`
	} `json:"revocations"`
}

func (r *Revocation) UpdateRevocations(data []byte) (err error) {
	var buf []jsonRevoke
	if err = json.Unmarshall(data, &buf); err != nil {
		log.Errorf("Error unmarshalling revocation json. " + err.Error())
		return err
	}

	for b := range buf {
		// TODO: if we refresh from a certain time, the force refresh will probably be
		// in that update and we are going to end up in an infinite loop. . .
		// add a forced param to the function call so we know this was forced?
		if b.ForceRefresh != "" {
			i, err := strconv.Atoi(b.ForceRefresh)
			if err != nil {
				log.Errorf("Erorr converting ForceRefresh to int. " + err.Error())
				continue
			}
			refreshCacheFromTime(i)
			continue
		}

		switch b.Properties {
		case "TOKEN":
			valid, i := isHashTimestampValid(b.Data.TokenHash, b.Data.RevokedAt)
			if !valid {
				log.Errorf("Invalid revocation data. TokenHash: %s, RevokedAt: %s", b.Data.TokenHash, b.Data.RevokedAt)
				continue
			}
			r.Tokens[b.Data.TokenHash] = i
		case "CLAIM":
			valid, i := isHashTimestampValid(b.Data.ValueHash, b.Data.IssuedBefore)
			if !valid {
				log.Errorf("Invalid revocation data. ValueHash: %s, IssuedBefore: %s", b.Data.ValueHash, b.Data.IssuedBefore)
				continue
			}
			r.Claims[b.Data.ValueHash] = i
		case "GLOBAL":
			i, err := strconv.Atoi(b.Data.IssuedBefore)
			if err != nil {
				log.Errorf("Erorr converting IssuedBefore to int. " + err.Error())
				continue
			}
			r.Gobal = i
		default:
			log.Errorf("Unsupported revocation property: %s", b.Properties)
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
