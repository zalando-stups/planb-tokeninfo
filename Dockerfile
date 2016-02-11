FROM busybox:ubuntu-14.04

EXPOSE 9021

COPY bin/planb-agent /
COPY bin/scm-source.json /

CMD /planb-agent
