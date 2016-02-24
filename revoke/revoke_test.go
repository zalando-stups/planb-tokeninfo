package revoke

import (
	"testing"
)

var j = []byte(`{
			  "meta": null,
			    "revocations": [
			    {
		      "type": "CLAIM",
		        "data": {
			        "name": "uid",
			        "value_hash": "+3sDm1MGB3+WGg7CzeMOBwse8V076MyYfNIF1W9A0B0=",
			        "hash_algorithm": "SHA-256",
			        "issued_before": 1456300677000
			      },
			      "revoked_at": 1456300677000
			    },
			    {
			    "type": "GLOBAL",
			    "data": {
			        "issued_before": 1456296158000
			      },
			    "revoked_at": 1456296158000
			    },
				{
			    "type": "TOKEN",
			    "data": {
			        "token_hash": "3AW57qxY0oO9RlVOW7zor7uUOFnoTNBSaYbEOYeJPRg=",
			        "hash_algorithm": "SHA-256"
			    },
			    "revoked_at": 1456302443000
			    }
			  ]
		}`)

func TestIsValidHashTimestampValid(t *testing.T) {
	if !isHashTimestampValid("hash", 123) {
		t.Errorf("Error validating hash and timestamp.")
	}
}

func TestIsValidHashTimestampInvalidHash(t *testing.T) {
	if isHashTimestampValid("", 123) {
		t.Errorf("Error validating hash.")
	}
}

func TestIsValidHashTimestampEmptyTimestamp(t *testing.T) {
	if isHashTimestampValid("hash", 0) {
		t.Errorf("Error validating timestamp.")
	}
}

func TestUnmarshalJsonData(t *testing.T) {

	var rev = new(jsonRevoke)
	rev.UnmarshallJSON(j)
	if rev.Meta.ForceRefresh != "" || len(rev.Revs) != 3 {
		t.Errorf("Error unmarshaling revocations\n\n%#v", rev)
	}
}

func TestGetRevocationFromJSONToken(t *testing.T) {
	var j = new(jsonRevocation)
	j.Type = "TOKEN"
	j.Data.TokenHash = "hash"
	j.RevokedAt = 123

	var r = new(Revocation)
	r.getRevocationFromJson(j)

	if r.Type != "TOKEN" ||
		r.Data["token_hash"] != "hash" ||
		r.Data["revoked_at"] != 123 {
		t.Errorf("Error getting revocation from jsonRevocation.")
	}
}

func TestGetRevocationFromJSONClaim(t *testing.T) {
	var j = new(jsonRevocation)
	j.Type = "CLAIM"
	j.Data.Name = "name"
	j.Data.ValueHash = "hash"
	j.Data.IssuedBefore = 123

	var r = new(Revocation)
	r.getRevocationFromJson(j)

	if r.Type != "CLAIM" ||
		r.Data["value_hash"] != "hash" ||
		r.Data["issued_before"] != 123 ||
		r.Data["name"] != "name" {
		t.Errorf("Error getting revocation from jsonRevocation.")
	}
}

func TestGetRevocationFromJSONGlobal(t *testing.T) {
	var j = new(jsonRevocation)
	j.Type = "GLOBAL"
	j.Data.IssuedBefore = 123

	var r = new(Revocation)
	r.getRevocationFromJson(j)

	if r.Type != "GLOBAL" ||
		r.Data["issued_before"] != 123 {
		t.Errorf("Error getting revocation from jsonRevocation.")
	}
}

func TestGetRevocationFromJSONInvalid(t *testing.T) {
	var j = new(jsonRevocation)
	j.Type = "INVALID"
	j.Data.Name = "name"
	j.Data.ValueHash = "hash"
	j.Data.IssuedBefore = 123

	var r = new(Revocation)
	r.getRevocationFromJson(j)
	if r.Type != "" {
		t.Errorf("Revocation type shouldn't be valid.")
	}
}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
