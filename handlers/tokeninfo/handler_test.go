package tokeninfo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/stretchr/testify/assert"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type mockKeyLoader int

const testJwtToken = "eyJraWQiOiJ0ZXN0a2V5IiwiYWxnIjoiRVMyNTYifQ.eyJpc3MiOiJQbGFuQiIsImV4cCI6MTQ1NTI0OTA5MywianRpIjoiVk9aS1JNYWZqOTN2N21sQzlRQnZ2QSIsImlhdCI6MTQ1NTIyMDI5Mywic3ViIjoiZm9vIiwic2NvcGUiOlsidWlkIl0sInJlYWxtIjoiL3Rlc3QiLCJ1aWQiOiJmb28ifQ.-x5QfZlaK2w6cXRMtmPV43E7yLgVoi_Ur9ybLnmHTPy5YknO0b2d0fBniTtLC95-JD_GEmxgBfbzRHl5RPQxew"

var testPubKey *ecdsa.PublicKey

func init() {
	x, _ := new(big.Int).SetString("115605682992956648477207773228188197675834354094591455680101846301827874884669", 10)
	y, _ := new(big.Int).SetString("95612535921063065667323916928898556799062466564160183670678964239934927686747", 10)
	testPubKey = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
}

func (kl *mockKeyLoader) LoadKey(id string) (interface{}, error) {
	return testPubKey, nil
}

func TestHandlerMissingToken(t *testing.T) {
	kl := new(mockKeyLoader)
	h := NewTokenInfoHandler(kl)
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/oauth2/tokeninfo", nil)
	h.ServeHTTP(rw, req)
	assert.Equal(t, 400, rw.Code)
	assert.Equal(t, "{\"error\":\"invalid_request\",\"error_description\":\"Access Token not valid\"}", rw.Body.String())
}

func TestHandler(t *testing.T) {
	kl := new(mockKeyLoader)
	h := NewTokenInfoHandler(kl)
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	url, _ := url.Parse("http://example.com/oauth2/tokeninfo?access_token=" + testJwtToken)
	req.URL = url
	h.ServeHTTP(rw, req)
	// TODO: find a reliable way of testing the success case
	// (test token expires expires)
	// assert.Equal(t, 200, rw.Code)
}

func BenchmarkHandler(b *testing.B) {
	kl := new(mockKeyLoader)
	h := NewTokenInfoHandler(kl)
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	url, _ := url.Parse("http://example.com/oauth2/tokeninfo?access_token=" + testJwtToken)
	req.URL = url
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.ServeHTTP(rw, req)
	}
}
