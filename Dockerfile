FROM registry.opensource.zalan.do/stups/ubuntu:15.10-14

EXPOSE 9021

COPY bin/planb-agent /
COPY bin/scm-source.json /

CMD /planb-agent
