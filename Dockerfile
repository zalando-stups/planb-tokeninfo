FROM busybox:ubuntu-14.04

EXPOSE 9021

# NOTE: we assume that our current working directory is $GOPATH
COPY bin/planb-tokeninfo /
COPY bin/scm-source.json /

CMD /planb-tokeninfo
