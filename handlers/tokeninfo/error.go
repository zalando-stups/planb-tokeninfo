package tokeninfo

import (
	"encoding/json"
	"net/http"
)

// error response format for the token info endpoint
// https://github.com/zalando/planb-tokeninfo/issues/11
type TokenInfoError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func writeError(w http.ResponseWriter, name string, descr string) {
	tie := TokenInfoError{Error: name, ErrorDescription: descr}
	str, err := json.Marshal(tie)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	w.Write(str)
}
