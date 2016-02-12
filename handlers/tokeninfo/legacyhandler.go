package tokeninffo

import (
	"encoding/json"
	"net/http"
)

type legacyTokenHandler struct {
}

func (h *legacyTokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if err := req.ParseForm(); err != nil {
		fmt.Errorf("Error reading http request. " + err.Error())
	}
	token := req.Form.Get("access_token")

	client := &http.Client{}
	newReq, _ := http.NewRequest("GET", TOKENINFO_LEGACY_URL+token, nil)
	res, err := client.Do(req)

	if err != nil {
		fmt.Errorf("Endpoint call failed. " + TOKENINFO_LEGACY_URL + ". " + err.Error())
	}
	w.Write(res)

	/*
		var ti TokenInfo

		err := json.Unmarshal(data, &ti)
		if err != nil {
			fmt.Errorf("Error unmarshalling data. " + err.Error())
		}
	*/
}
func DefaultLegacyTokenHandler() http.Handler {
	return NewLegacyTokenHandler()
}

func NewLegacyTokenHandler() http.Handler {
	return &legacyTokenHandler{}
}
