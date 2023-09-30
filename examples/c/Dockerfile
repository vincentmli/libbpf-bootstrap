FROM ubuntu:latest 

RUN apt-get update && \
    apt-get install -y libelf1 \
                       iptables \
                       iproute2 

COPY xdp-iptables.sh /usr/local/bin
COPY bpftool /usr/local/bin
COPY xdppacket /usr/local/bin

#ENTRYPOINT ["/usr/local/bin/xdppacket", "--iface", "ens192", "--mss4", "1460", "--mss6", "1440", "--wscale", "7", "--ttl", "254", "--ports", "80,8080"]

ENTRYPOINT ["/usr/local/bin/xdp-iptables.sh"]
