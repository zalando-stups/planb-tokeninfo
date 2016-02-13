package tokeninfo

import (
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRouterMissingToken(t *testing.T) {
	h := DefaultTokenRouterHandler()
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "http://example.com/oauth2/tokeninfo", nil)
	h.ServeHTTP(rw, req)
	assert.Equal(t, 400, rw.Code)
	assert.Equal(t, "{\"error\":\"invalid_request\",\"error_description\":\"no token present in request\"}", rw.Body.String())
}

func TestIsJWT(t *testing.T) {
	assert.Equal(t, isJWTToken("xx"), false)
	assert.Equal(t, isJWTToken("a.b.c"), true)
}
