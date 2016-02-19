package revoke

import (
	"testing"
)

func TestIsValidHashTimestampValid(t *testing.T) {
	if !isHashTimestampValid("hash", "123") {
		t.Errorf("Error validating hash and timestamp.")
	}
}

func TestIsValidHashTimestampInvalidHash(t *testing.T) {
	if isHashTimestampValid("", "123") {
		t.Errorf("Error validating hash.")
	}
}

func TestIsValidHashTimestampInvalidTimestamp(t *testing.T) {
	if isHashTimestampValid("hash", "abc") {
		t.Errorf("Error validating timestamp.")
	}
}

func TestIsValidHashTimestampEmptyTimestamp(t *testing.T) {
	if isHashTimestampValid("hash", "") {
		t.Errorf("Error validating timestamp.")
	}
}

/*
func TestGetRevocationFromJSONToken(t *testing.T) {
	var j = []byte(`{"meta": "null", "revocations": ["type": "TOKEN", "revoked_at": "123", "data": {"token_hash": "hash", "revoked_at": "123"}]}`)

	var rev = new(jsonRevoke)
	rev.UnmarshallJSON(j)

	if rev.Meta.ForceRefresh != "" ||
		rev.Revs[0].Type != "TOKEN" ||
		rev.Revs[0].RevokedAt != "123" ||
		rev.Revs[0].Data.TokenHash != "hash" ||
		rev.Revs[0].Data.RevokedAt != "123" {
		t.Errorf("Failed to unmarshal revocation data.")
	}
}
*/

func TestGetRevocationFromJSONToken(t *testing.T) {
	var j = new(jsonRevocation)
	j.Type = "TOKEN"
	j.Data.TokenHash = "hash"
	j.Data.RevokedAt = "123"

	var r = new(Revocation)
	r.getRevocationFromJson(j)

	if r.Type != "TOKEN" ||
		r.Data["token_hash"] != "hash" ||
		r.Data["revoked_at"] != "123" {
		t.Errorf("Error getting revocation from jsonRevocation.")
	}
}

func TestGetRevocationFromJSONClaim(t *testing.T) {
	var j = new(jsonRevocation)
	j.Type = "CLAIM"
	j.Data.Name = "name"
	j.Data.ValueHash = "hash"
	j.Data.IssuedBefore = "123"

	var r = new(Revocation)
	r.getRevocationFromJson(j)

	if r.Type != "CLAIM" ||
		r.Data["value_hash"] != "hash" ||
		r.Data["issued_before"] != "123" ||
		r.Data["name"] != "name" {
		t.Errorf("Error getting revocation from jsonRevocation.")
	}
}

func TestGetRevocationFromJSONGlobal(t *testing.T) {
	var j = new(jsonRevocation)
	j.Type = "GLOBAL"
	j.Data.IssuedBefore = "123"

	var r = new(Revocation)
	r.getRevocationFromJson(j)

	if r.Type != "GLOBAL" ||
		r.Data["issued_before"] != "123" {
		t.Errorf("Error getting revocation from jsonRevocation.")
	}
}

func TestGetRevocationFromJSONInvalid(t *testing.T) {
	var j = new(jsonRevocation)
	j.Type = "INVALID"
	j.Data.Name = "name"
	j.Data.ValueHash = "hash"
	j.Data.IssuedBefore = "123"

	var r = new(Revocation)
	r.getRevocationFromJson(j)
	if r.Type != "" {
		t.Errorf("Revocation type shouldn't be valid.")
	}
}

// vim: ts=4 sw=4 noexpandtab nolist syn=go
