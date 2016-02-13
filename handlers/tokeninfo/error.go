package tokeninfo

// error response format for the token info endpoint
// https://github.com/zalando/planb-tokeninfo/issues/11
type TokenInfoError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}
