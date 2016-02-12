package tokeninfo

const (
	testToken = "eyJraWQiOiJ0ZXN0a2V5IiwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJQbGFuQiIsImV4cCI6MTQ1NTI0OTA5MywianRpIjoiVk9aS1JNYWZqOTN2N21sQzlRQnZ2QSIsImlhdCI6MTQ1NTIyMDI5Mywic3ViIjoiZm9vIiwic2NvcGUiOlsidWlkIl0sInJlYWxtIjoiL3Rlc3QiLCJ1aWQiOiJmb28ifQ.-x5QfZlaK2w6cXRMtmPV43E7yLgVoi_Ur9ybLnmHTPy5YknO0b2d0fBniTtLC95-JD_GEmxgBfbzRHl5RPQxew"
)

var (
	testKey = map[string]interface{}{
		"alg": "ES256",
		"crv": "P-256",
		"kid": "testkey",
		"kty": "EC",
		"use": "sign",
		"x":   "_5Z_cB5zhjVCt_GMfiC6sSBos0podt-YJicV6_GzDD0",
		"y":   "02LHDzZYup0SlbuqjNPBhr2X_LGamSgRidzKXsA0TFs",
	}
)
