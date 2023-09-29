FROM ubuntu:latest 

RUN apt-get update && \
    apt-get install -y libelf1 \
                       iptables \
                       iproute2 

COPY xdp-iptables.sh /usr/local/bin
COPY bpftool /usr/local/bin
COPY xdppacket /usr/local/bin

