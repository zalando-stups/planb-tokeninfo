package revoke

import (
	"encoding/json"
	"log"
<<<<<<< HEAD
=======
	"strconv"
>>>>>>> fixed build bugs. refactored json structs.
	"time"
)

type Revocation struct {
	Type      string // token, claim, global
	Data      map[string]interface{}
	Timestamp int
}

type jsonRevoke struct {
	Meta struct {
		ForceRefresh string `json:"force_refresh"`
	} `json:"meta"`
	Revs []jsonRevocation `json:"revocations"`
}

type jsonRevocation struct {
	Type      string `json:"type"` // TOKEN, CLAIM, GLOBAL
<<<<<<< HEAD
	RevokedAt int    `json:"revoked_at"`
	Data      struct {
		Name          string `json:"name,omitempty"`           // CLAIM
		ValueHash     string `json:"value_hash,omitempty"`     // CLAIM
		IssuedBefore  int    `json:"issued_before,omitempty"`  // CLAIM, GLOBAL
		TokenHash     string `json:"token_hash,omitempty"`     // TOKEN
		HashAlgorithm string `json:"hash_algorithm,omitempty"` // CLAIM, TOKEN
=======
	RevokedAt string `json:"revoked_at"`
	Data      struct {
		Name         string `json:"name,omitempty"`          // CLAIM
		ValueHash    string `json:"value_hash,omitempty"`    // CLAIM
		IssuedBefore string `json:"issued_before,omitempty"` // CLAIM, GLOBAL
		TokenHash    string `json:"token_hash,omitempty"`    // TOKEN
		RevokedAt    string `json:"revoked_at,omitempty"`    // TOKEN
>>>>>>> fixed build bugs. refactored json structs.
	} `json:"data"`
}

func (r *jsonRevoke) UnmarshallJSON(data []byte) (err error) {
<<<<<<< HEAD
	if err = json.Unmarshal(data, &r); err != nil {
=======
	var buf jsonRevoke
	if err = json.Unmarshal(data, &buf); err != nil {
>>>>>>> fixed build bugs. refactored json structs.
		log.Println("Error unmarshalling revocation json. " + err.Error())
		return err
	}

	// Note: if we already foreced a refresh, we don't want to do it again
	// otherwise we'll get stuck in an infinite loop
	/*
		if buf.ForceRefresh != "" && !forcedRefresh {
			i, err := strconv.Atoi(buf.ForceRefresh)
			if err != nil {
				log.Println("Error converting ForceRefresh to int." + err.Error())
			} else {
				// TODO: not sure how to get the current Cache from here. . .
				refreshCacheFromTime(i)
			}
		}
	*/

	return
}

func (r *Revocation) getRevocationFromJson(j *jsonRevocation) {

<<<<<<< HEAD
	// account for some network delay, say three seconds
	t := int(time.Now().UnixNano()/1e6) - 3*1e6

	r.Data = make(map[string]interface{})
	switch j.Type {
	case "TOKEN":
		valid := isHashTimestampValid(j.Data.TokenHash, j.RevokedAt)
		if !valid {
			log.Println("Invalid revocation data (TOKEN). TokenHash: %s, RevokedAt: %d", j.Data.TokenHash, j.RevokedAt)
			return
		}
		r.Data["token_hash"] = j.Data.TokenHash
		r.Data["revoked_at"] = j.RevokedAt
	case "CLAIM":
		valid := isHashTimestampValid(j.Data.ValueHash, j.Data.IssuedBefore)
		if !valid {
			log.Println("Invalid revocation data (CLAIM). ValueHash: %s, IssuedBefore: %d", j.Data.ValueHash, j.Data.IssuedBefore)
			return
		}
		if j.Data.Name == "" {
			log.Println("Invalid revocation data (missing claim name).")
			return
=======
	t := int(time.Now().Unix())

	switch j.Type {
	case "TOKEN":
		valid := isHashTimestampValid(j.Data.TokenHash, j.Data.RevokedAt)
		if !valid {
			log.Println("Invalid revocation data. TokenHash: %s, RevokedAt: %s", j.Data.TokenHash, j.Data.RevokedAt)
			continue
		}
		r.Data["token_hash"] = j.Data.TokenHash
		r.Data["revoked_at"] = j.Data.RevokedAt
	case "CLAIM":
		valid := isHashTimestampValid(j.Data.ValueHash, j.Data.IssuedBefore)
		if !valid {
			log.Println("Invalid revocation data. ValueHash: %s, IssuedBefore: %s", j.Data.ValueHash, j.Data.IssuedBefore)
			continue
>>>>>>> fixed build bugs. refactored json structs.
		}
		r.Data["value_hash"] = j.Data.ValueHash
		r.Data["issued_before"] = j.Data.IssuedBefore
		r.Data["name"] = j.Data.Name
	case "GLOBAL":
<<<<<<< HEAD
		valid := isHashTimestampValid("thisStringDoesntMatter", j.Data.IssuedBefore)
		if !valid {
			log.Println("Invalid revocation data (GLOBAL). IssuedBefore: %d", j.Data.IssuedBefore)
			return
=======
		_, err := strconv.Atoi(j.Data.IssuedBefore)
		if err != nil {
			log.Println("Erorr converting IssuedBefore to int. " + err.Error())
			continue
>>>>>>> fixed build bugs. refactored json structs.
		}
		r.Data["issued_before"] = j.Data.IssuedBefore
	default:
		log.Println("Unsupported revocation type: %s", j.Type)
<<<<<<< HEAD
		return
=======
		continue
>>>>>>> fixed build bugs. refactored json structs.
	}

	r.Type = j.Type
	r.Timestamp = t
	return
}

<<<<<<< HEAD
func isHashTimestampValid(hash string, timestamp int) bool {
	return hash != "" && timestamp != 0
=======
func isHashTimestampValid(hash, timestamp string) bool {
	if hash == "" || timestamp == "" {
		return false
	}

	_, err := strconv.Atoi(timestamp)
	if err != nil {
		log.Println("Erorr converting timestamp to int. " + err.Error())
		return false
	}

	return true

>>>>>>> fixed build bugs. refactored json structs.
}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
