=======================
Plan B Token Info Agent
=======================

.. image:: https://travis-ci.org/zalando/planb-agent.svg?branch=master
    :target: https://travis-ci.org/zalando/planb-agent

WORK IN PROGRESS

Requires Go 1.5.1.

.. code-block:: bash

    $ sudo apt-get install golang  # how to install Go on Ubuntu 15.10
    $ export GOPATH=$(pwd)         # first set GOPATH if not done already
    $ go get -t github.com/zalando/planb-agent
    $ go test github.com/zalando/planb-agent
    $ go install github.com/zalando/planb-agent

Running
=======

.. code-block:: bash

    $ export OPENID_PROVIDER_CONFIGURATION_URL=https://planb-provider.example.org/.well-known/openid-configuration
    $ $GOPATH/bin/planb-agent  # start server on port 9021

Now we can test our token info endpoint with a valid JWT access token:

.. code-block:: bash

    $ curl localhost:9021/oauth2/tokeninfo?access_token=MjoxLjUuMS0wdW..
