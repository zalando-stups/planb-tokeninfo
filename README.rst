=========================
Plan B Token Info Service
=========================

.. image:: https://travis-ci.org/zalando/planb-tokeninfo.svg?branch=master
    :target: https://travis-ci.org/zalando/planb-tokeninfo

.. image:: https://codecov.io/github/zalando/planb-tokeninfo/coverage.svg?branch=master
    :target: https://codecov.io/github/zalando/planb-tokeninfo?branch=master

.. image:: https://goreportcard.com/badge/github.com/zalando/planb-tokeninfo
    :target: https://goreportcard.com/report/github.com/zalando/planb-tokeninfo

.. image:: https://readthedocs.org/projects/planb/badge/?version=latest
   :target: https://readthedocs.org/projects/planb/?badge=latest
   :alt: Documentation Status

Lightweight service providing an OAuth 2 token info HTTP endpoint to validate JWT tokens issued by the `Plan B OpenID Connect Provider`_.

Current features:

* Download public keys (`set of JWKs`_) from OpenID provider
* Verify signed JWT tokens using the right public key (identified by "kid" `JOSE header`_)
* Proxy to upstream tokeninfo for non-JWT tokens and cache the response

Planned features:

* Download revocation lists from `Plan B Revocation Service`_
* Deny JWT tokens matching any revocation list

More information is available in our `Plan B Documentation`_.


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
``UPSTREAM_CACHE_MAX_SIZE``
    Maximum number of entries for upstream token cache. It defaults to 10000.
``UPSTREAM_CACHE_TTL``
    The TTL for upstream token cache entries. It defaults to 60 seconds. Zero will disable the cache. See also `Time based settings`_
``REVOCATION_PROVIDER_URL``
    URL of of the Revocation service.
``REVOCATION_PROVIDER_REFRESH_INTERVAL``
    Refresh interval for polling the Revocation service. See `Time based settings`_
``REVOCATION_CACHE_TTL``
    The TTL for Revocation cache entries. Default is 8 hours. See `Time based settings`_
``HASHING_SALT``
    Shared salt with Revocation service. Used for comparing hashed tokens from the Revocation service.
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

Metrics
=======

Metrics are exposed by default on port 9020 "/metrics". They include:

``planb.openidprovider.numkeys``
    Number of public keys in memory.
``planb.tokeninfo.proxy``
    Timer for the proxy handler (includes cached results and upstream calls).
``planb.tokeninfo.proxy.cache.hits``
    Number of upstream cache hits.
``planb.tokeninfo.proxy.cache.misses``
    Number of upstream cache misses.
``planb.tokeninfo.proxy.cache.expirations``
    Number of upstream cache misses because of expiration.
``planb.tokeninfo.proxy.upstream``
    Timer for calls to the upstream tokeninfo. Cached responses are not measured here.

.. _Plan B OpenID Connect Provider: https://github.com/zalando/planb-provider
.. _Plan B Revocation Service: https://github.com/zalando/planb-revocation
.. _Plan B Documentation: http://planb.readthedocs.org/
.. _JOSE header: https://tools.ietf.org/html/rfc7515#section-4
.. _set of JWKs: https://tools.ietf.org/html/rfc7517#section-5
.. _OpenID Connect configuration discovery document: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
