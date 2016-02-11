package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

const (
	port = ":9021"
)

func getHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func getTokenInfo(w http.ResponseWriter, r *http.Request) {
	ti, err := validateToken(r)
	if err != nil {
		sendError(w, http.StatusUnauthorized)
		return
	}

	resp, err := json.Marshal(ti)
	if err != nil {
		sendError(w, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func sendError(w http.ResponseWriter, status int) {
	w.WriteHeader(status)
	w.Write([]byte("Request error"))
}

func main() {
	fmt.Printf("Started server at %v.\n", port)
	http.HandleFunc("/health", getHealth)
	http.HandleFunc("/oauth2/tokeninfo", getTokenInfo)
	log.Fatal(http.ListenAndServe(port, nil))
}
