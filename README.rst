=========================
Plan B Token Info Service
=========================

.. image:: https://travis-ci.org/zalando/planb-tokeninfo.svg?branch=master
    :target: https://travis-ci.org/zalando/planb-tokeninfo

.. image:: https://codecov.io/github/zalando/planb-tokeninfo/coverage.svg?branch=master
    :target: https://codecov.io/github/zalando/planb-tokeninfo?branch=master

Lightweight service providing an OAuth 2 token info HTTP endpoint to validate JWT tokens issued by the `Plan B OpenID Connect Provider`_.

(Planned) Features:

* Download public keys (`set of JWKs`_) from OpenID provider
* Verify signed JWT tokens using the right public key (identified by "kid" `JOSE header`_)
* Download revocation lists from `Plan B Revocation Service`_
* Deny JWT tokens matching any revocation list


Building
========

Requires Go 1.5.1 or higher.

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

Configuration
=============

The following environment variables are supported:

``OPENID_PROVIDER_CONFIGURATION_URL``
    URL of the `OpenID Connect configuration discovery document`_ containing the ``jwk_uri`` which points to a `set of JWKs`_.
``UPSTREAM_TOKENINFO_URL``
    URL of upstream OAuth 2 token info for non-JWT Bearer tokens.


.. _Plan B OpenID Connect Provider: https://github.com/zalando/planb-provider
.. _Plan B Revocation Service: https://github.com/zalando/planb-revocation
.. _JOSE header: https://tools.ietf.org/html/rfc7515#section-4
.. _set of JWKs: https://tools.ietf.org/html/rfc7517#section-5
.. _OpenID Connect configuration discovery document: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse
