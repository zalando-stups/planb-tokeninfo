package jwks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"github.com/zalando/planb-tokeninfo/keyloader/openid/jwk"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

const (
	rsaModulus = "3gBi3ty-R5LoakA7_NJvHjYoGg-HenWIP5zjYm5x" +
		"5weefTqcTYBzB1fimX4g3_KE5jsOZjRcT3kgSdxcgTF82eLzyjxQ9XTb7pm066ES8e7YRxmM" +
		"km5VknCV_KAmacQRisGUDcymMKYyrS6ooGVSMtzrUjPVMm7UF3zh1c4rAvhgVjsEPc7XfiOr" +
		"R2cGDW91jowstrLXHaqjC2FSt_1kWjW5JWwqUPl9Ef9dCORq1ZWVC60kzq99yArnm8DVbwr6" +
		"aMEJBTI8ZBRk6vG8TfuttlTfTngrF6pA1bD5_CL1pGe0Kjs4RoVSODSlmrPxzDPmxvtY_k4s" +
		"kFEo0sVdfG0Rlw"
	ecdsaX = "FDrM1mhj9Q4gvELNEVSe6UPKNjjVuAtgt04ro9dCchU"
	ecdsaY = "HTGUAM_1N_9bDYOW2W_nRDX64JXw41ja6DxpbSPaEsA"
)

type mockKeyLoader struct {
	theKeys map[string]interface{}
}

func (kl *mockKeyLoader) LoadKey(id string) (interface{}, error) { return nil, nil }
func (kl *mockKeyLoader) Keys() map[string]interface{}           { return kl.theKeys }

func mockValidKeys() map[string]interface{} {
	return map[string]interface{}{
		"key1": jwk.JSONWebKey{
			Algorithm: "RS256",
			KeyID:     "key1",
			Use:       "sig",
			Key: &rsa.PublicKey{
				E: 65537, // AQAB base64 encoded
				N: new(big.Int).SetBytes(mustDecode(rsaModulus)),
			},
		},
		"key2": jwk.JSONWebKey{
			Algorithm: "ES256",
			KeyID:     "key2",
			Use:       "sig",
			Key: &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(mustDecode(ecdsaX)),
				Y:     new(big.Int).SetBytes(mustDecode(ecdsaY)),
			},
		},
	}
}

func mustDecode(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestHandler(t *testing.T) {
	mockKeys := mockValidKeys()
	kl := &mockKeyLoader{theKeys: mockKeys}
	h := Handler(kl)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "http://example.com/oauth2/v3/keys", nil)

	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Wrong status code. Wanted %q, got %q", http.StatusText(http.StatusOK), http.StatusText(w.Code))
	}

	jwks := new(jwk.JSONWebKeySet)
	if err := json.NewDecoder(w.Body).Decode(jwks); err != nil {
		t.Error("Failed to recover the response to a JWKS object")
	}

	m := jwks.ToMap()
	if !reflect.DeepEqual(m, mockKeys) {
		t.Error("JWKS doesn't match the original")
	}
}

func TestFailure(t *testing.T) {
	kl := &mockKeyLoader{theKeys: map[string]interface{}{"foo": "bar"}}
	h := Handler(kl)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "http://example.com/oauth2/v3/keys", nil)

	h.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Wrong status code. Wanted %q, got %q", http.StatusText(http.StatusInternalServerError),
			http.StatusText(w.Code))
	}
}
