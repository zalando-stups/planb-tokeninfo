package options

import (
	"log"
	"net/url"
	"os"
)

var (
	UpstreamTokeninfoUrl           *url.URL
	OpenIdProviderConfigurationUrl *url.URL
)

func init() {
	url, err := getUrl("UPSTREAM_TOKENINFO_URL")
	if err != nil {
		log.Fatal("Error with the upstream url: ", err)
	}
	UpstreamTokeninfoUrl = url

	url, err = getUrl("OPENID_PROVIDER_CONFIGURATION_URL")
	if err != nil {
		log.Fatal("Error with the OpenID provider configuration url: ", err)
	}
	OpenIdProviderConfigurationUrl = url
}

func getUrl(v string) (*url.URL, error) {
	return url.Parse(os.Getenv(v))
}
