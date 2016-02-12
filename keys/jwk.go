package keys

type jsonWebKey map[string]interface{}

type jsonWebKeySet struct {
	Keys []jsonWebKey `json:"keys"`
}
