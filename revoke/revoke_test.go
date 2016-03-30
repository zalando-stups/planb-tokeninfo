package revoke

import (
	"encoding/json"
	"testing"
	"time"
)

var j = []byte(`{
			  "meta": {"REFRESH_FROM": 10000, "REFRESH_TIMESTAMP": 10000},
			    "revocations": [
			    {
		      "type": "CLAIM",
		        "data": {
			        "names": ["uid"],
			        "value_hash": "+3sDm1MGB3+WGg7CzeMOBwse8V076MyYfNIF1W9A0B0=",
			        "hash_algorithm": "SHA-256",
			        "issued_before": 1456300677
			      },
			      "revoked_at": 1456300677
			    },
			    {
			    "type": "GLOBAL",
			    "data": {
			        "issued_before": 1456296158
			      },
			    "revoked_at": 1456296158
			    },
				{
			    "type": "TOKEN",
			    "data": {
			        "token_hash": "3AW57qxY0oO9RlVOW7zor7uUOFnoTNBSaYbEOYeJPRg=",
			        "hash_algorithm": "SHA-256"
			    },
			    "revoked_at": 1456302443
			    },
			    {
		      "type": "CLAIM",
		        "data": {
			        "names": ["sub", "uid"],
			        "value_hash": "13sDm1MGB3+WGg7CzeMOBwse8V076MyYfNIF1W9A0B0=",
			        "hash_algorithm": "SHA-256",
			        "issued_before": 1456300677
			      },
			      "revoked_at": 1456300677
			    }
			  ]
		}`)

func TestGetRevocationFromJSONToken(t *testing.T) {

	var rev = &jsonRevoke{}
	json.Unmarshal(j, &rev)

	r, _ := getRevocationFromJson(rev.Revs[2])

	if r.Type != REVOCATION_TYPE_TOKEN ||
		r.Data["token_hash"] != "3AW57qxY0oO9RlVOW7zor7uUOFnoTNBSaYbEOYeJPRg=" ||
		r.Data["revoked_at"] != 1456302443 {
		t.Errorf("Error getting revocation from jsonRevocation. jsonRev: %#v\n\nRevocation: %#v", rev.Revs[2], r)
	}
}

func TestGetRevocationFromJSONClaim(t *testing.T) {

	var rev = &jsonRevoke{}
	json.Unmarshal(j, &rev)

	r, _ := getRevocationFromJson(rev.Revs[0])

	if r.Type != REVOCATION_TYPE_CLAIM ||
		r.Data["value_hash"] != "+3sDm1MGB3+WGg7CzeMOBwse8V076MyYfNIF1W9A0B0=" ||
		r.Data["issued_before"] != 1456300677 ||
		r.Data["names"] != "uid" {
		t.Errorf("Error getting revocation from jsonRevocation. jsonRev: %#v\n\nRevocation: %#v", rev.Revs[0], r)
	}
}

func TestGetRevocationFromJSONMutliNameClaim(t *testing.T) {
	var rev = &jsonRevoke{}
	json.Unmarshal(j, &rev)

	r, _ := getRevocationFromJson(rev.Revs[3])

	if r.Type != REVOCATION_TYPE_CLAIM ||
		r.Data["value_hash"] != "13sDm1MGB3+WGg7CzeMOBwse8V076MyYfNIF1W9A0B0=" ||
		r.Data["issued_before"] != 1456300677 ||
		r.Data["names"] != "sub|uid" {
		t.Errorf("Error getting revocation from jsonRevocation. jsonRev: %#v\n\nRevocation: %#v", rev.Revs[3], r)
	}
}

func TestGetRevocationFromJSONGlobal(t *testing.T) {

	var rev = &jsonRevoke{}
	json.Unmarshal(j, &rev)

	r, _ := getRevocationFromJson(rev.Revs[1])

	if r.Type != REVOCATION_TYPE_GLOBAL ||
		r.Data["issued_before"] != 1456296158 {
		t.Errorf("Error getting revocation from jsonRevocation. jsonRev: %#v\n\nRevocation: %#v", rev.Revs[1], r)
	}
}

func TestGetRevocationFromJSONInvalidType(t *testing.T) {
	var j = &jsonRevocation{}
	j.Type = "INVALID"
	j.RevokedAt = 222
	j.Data.Names = []string{"name"}
	j.Data.ValueHash = "hash"
	j.Data.IssuedBefore = 123

	if _, err := getRevocationFromJson(j); err == nil {
		t.Errorf("Revocation shouldn't be valid.")
	}
}

func TestGetRevocationFromJSONInvalidClaimName(t *testing.T) {
	var j = &jsonRevocation{}
	j.Type = REVOCATION_TYPE_CLAIM
	j.RevokedAt = 222
	j.Data.Names = nil
	j.Data.ValueHash = "hash"
	j.Data.IssuedBefore = 123

	if _, err := getRevocationFromJson(j); err == nil {
		t.Errorf("Revocation shouldn't be valid.")
	}
}

func TestGetRevocationFromJSONInvalidClaimHash(t *testing.T) {
	var j = &jsonRevocation{}
	j.Type = REVOCATION_TYPE_CLAIM
	j.RevokedAt = 222
	j.Data.Names = []string{"name"}
	j.Data.ValueHash = ""
	j.Data.IssuedBefore = 123

	if _, err := getRevocationFromJson(j); err == nil {
		t.Errorf("Revocation shouldn't be valid.")
	}
}

func TestGetRevocationFromJSONInvalidClaimTS(t *testing.T) {
	var j = &jsonRevocation{}
	j.Type = REVOCATION_TYPE_CLAIM
	j.RevokedAt = 222
	j.Data.Names = []string{"name"}
	j.Data.ValueHash = "abc"
	j.Data.IssuedBefore = 0

	if _, err := getRevocationFromJson(j); err == nil {
		t.Errorf("Revocation shouldn't be valid.")
	}

	j.RevokedAt = 0
	j.Data.IssuedBefore = 222
	if _, err := getRevocationFromJson(j); err == nil {
		t.Errorf("Revocation shouldn't be valid.")
	}

	j.RevokedAt = 0
	j.Data.IssuedBefore = 0
	if _, err := getRevocationFromJson(j); err == nil {
		t.Errorf("Revocation shouldn't be valid.")
	}
}

func TestGetRevocationFromJSONInvalidTokenHash(t *testing.T) {
	var j = &jsonRevocation{}
	j.Type = REVOCATION_TYPE_TOKEN
	j.RevokedAt = 222
	j.Data.TokenHash = ""
	j.Data.IssuedBefore = 123

	if _, err := getRevocationFromJson(j); err == nil {
		t.Errorf("Revocation shouldn't be valid.")
	}
}

func TestGetRevocationFromJSONInvalidTokenTS(t *testing.T) {
	var j = &jsonRevocation{}
	j.Type = REVOCATION_TYPE_TOKEN
	j.Data.TokenHash = "abc"

	if _, err := getRevocationFromJson(j); err == nil {
		t.Errorf("Revocation shouldn't be valid.")
	}

}

func TestGetRevocationFromJSONInvalidGlobalIssuedBefore(t *testing.T) {
	var j = &jsonRevocation{}
	j.Type = REVOCATION_TYPE_GLOBAL
	j.RevokedAt = 123456
	j.Data.IssuedBefore = int(time.Now().Add(10 * time.Second).Unix())

	if _, err := getRevocationFromJson(j); err == nil {
		t.Errorf("Revocation shouldn't be valid.")
	}

	j.Data.IssuedBefore = 0
	if _, err := getRevocationFromJson(j); err == nil {
		t.Errorf("Revocation shouldn't be valid.")
	}
}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
