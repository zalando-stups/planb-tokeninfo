package openid

// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
type configuration struct {
	Issuer  string `json:"issuer"`
	JwksURI string `json:"jwks_uri"`
	/* and more... */
}
