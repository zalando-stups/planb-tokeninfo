package keys

// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
type configuration struct {
	Issuer  string `json:"issuer"`
	JwksUri string `json:"jwks_uri"`
	/* and more... */
}
