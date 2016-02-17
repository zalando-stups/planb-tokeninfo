package ht

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCustomUserAgent(t *testing.T) {

	handler := func(w http.ResponseWriter, req *http.Request) {
		ua := req.Header.Get("User-Agent")
		if ua != UserAgent {
			t.Errorf("Wrong user agent header. Wanted %q, got %q", UserAgent, ua)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}

	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()

	url := fmt.Sprintf("http://%s", server.Listener.Addr())
	resp, err := Get(url)
	if err != nil {
		t.Fatal(err)
	}

	defer resp.Body.Close()
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if string(buf) != "OK" {
		t.Errorf("Unexpected response. Wanted OK, got %q", buf)
	}
}

func TestInvalidUrl(t *testing.T) {
	_, err := Get("http://192.168.0.%31/")
	if err == nil {
		t.Error("Expected an error")
	}
}
