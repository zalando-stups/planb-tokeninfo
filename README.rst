=========================
Plan B Token Info Service
=========================

.. image:: https://travis-ci.org/zalando/planb-tokeninfo.svg?branch=master
    :target: https://travis-ci.org/zalando/planb-tokeninfo

.. image:: https://codecov.io/github/zalando/planb-tokeninfo/coverage.svg?branch=master
    :target: https://codecov.io/github/zalando/planb-tokeninfo?branch=master

.. image:: https://goreportcard.com/badge/github.com/zalando/planb-tokeninfo
    :target: https://goreportcard.com/report/github.com/zalando/planb-tokeninfo

Lightweight service providing an OAuth 2 token info HTTP endpoint to validate JWT tokens issued by the `Plan B OpenID Connect Provider`_.

(Planned) Features:

* Download public keys (`set of JWKs`_) from OpenID provider
* Verify signed JWT tokens using the right public key (identified by "kid" `JOSE header`_)
* Download revocation lists from `Plan B Revocation Service`_
* Deny JWT tokens matching any revocation list


Building
========

Requires Go 1.5 or higher.

.. code-block:: bash

    $ sudo apt-get install golang  # how to install Go on Ubuntu 15.10
    $ export GOPATH=$(pwd)         # first set GOPATH if not done already
    $ go get -t github.com/zalando/planb-tokeninfo
    $ go test github.com/zalando/planb-tokeninfo/...
    $ go install github.com/zalando/planb-tokeninfo

Running
=======

.. code-block:: bash

    $ export OPENID_PROVIDER_CONFIGURATION_URL=https://planb-provider.example.org/.well-known/openid-configuration
    $ export UPSTREAM_TOKENINFO_URL=https://auth.example.org/oauth2/tokeninfo
    $ $GOPATH/bin/planb-tokeninfo  # start server on port 9021

Now we can test our token info endpoint with a valid JWT access token:

.. code-block:: bash

    $ # using the Authorization header is the preferred method
    $ curl -H 'Authorization: Bearer MjoxLjUuMS0wdW..' localhost:9021/oauth2/tokeninfo
    $ # simple GET query parameter works too (not recommended!)
    $ curl localhost:9021/oauth2/tokeninfo?access_token=MjoxLjUuMS0wdW..

Running with Docker:

.. code-block:: bash

    $ TAG=$(curl https://registry.opensource.zalan.do/teams/stups/artifacts/planb-tokeninfo/tags | jq -r .[].name | tail -n 1)
    $ docker run -it -v /etc/ssl/certs:/etc/ssl/certs -p 9021:9021 -e OPENID_PROVIDER_CONFIGURATION_URL=https://planb-provider.example.org/.well-known/openid-configuration registry.opensource.zalan.do/stups/planb-tokeninfo:$TAG

Configuration
=============

The following environment variables are supported:

``OPENID_PROVIDER_CONFIGURATION_URL``
    URL of the `OpenID Connect configuration discovery document`_ containing the ``jwks_uri`` which points to a `set of JWKs`_.
``OPENID_PROVIDER_REFRESH_INTERVAL``
    The OpenID Connect configuration refresh interval. See `Time based settings`_
``UPSTREAM_TOKENINFO_URL``
    URL of upstream OAuth 2 token info for non-JWT Bearer tokens.
``LISTEN_ADDRESS``
    The address for the application listener. It defaults to ':9021'
``METRICS_LISTEN_ADDRESS``
    The address for the metrics listener. Should be different from the application listener. It defaults to ':9020'
``HTTP_CLIENT_TIMEOUT``
    The timeout for the default HTTP client. See `Time based settings`_
``HTTP_CLIENT_TLS_TIMEOUT``
    The timeout for the default HTTP client when using TLS. See `Time based settings`_

Time based settings
-------------------

Some of the above settings accept time based definitions. Those definitions can be specified as a string that can be understood by time.ParseDuration().
For ex., '10s' for 10 seconds, '1h10m' for 1 hour and 10 minutes, '100ms' for 100 milliseconds.
A simple numeric value is interpreted as Seconds. For ex., '30' is interpreted as 30 seconds.

.. _Plan B OpenID Connect Provider: https://github.com/zalando/planb-provider
.. _Plan B Revocation Service: https://github.com/zalando/planb-revocation
.. _JOSE header: https://tools.ietf.org/html/rfc7515#section-4
.. _set of JWKs: https://tools.ietf.org/html/rfc7517#section-5
.. _OpenID Connect configuration discovery document: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
