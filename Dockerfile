# NOTE: we use our Zalando base image to have the Zalando CA
FROM registry.opensource.zalan.do/stups/ubuntu:15.10-14

EXPOSE 9021

# NOTE: we assume that our current working directory is $GOPATH
COPY bin/planb-agent /
COPY bin/scm-source.json /

CMD /planb-agent
