FROM registry.opensource.zalan.do/stups/ubuntu:15.10-14

EXPOSE 9021

COPY src/github.com/zalando/planb-agent/agent /planb-agent

CMD /planb-agent
