#!/bin/bash

interface=$1
sysctl -w net.ipv4.tcp_syncookies=2
sysctl -w net.ipv4.tcp_timestamps=1
sysctl -w net.netfilter.nf_conntrack_tcp_loose=0
iptables -t raw -I PREROUTING  -i $interface -p tcp -m tcp --syn --dport 80 -j CT --notrack
iptables -t filter -A INPUT -i $interface -p tcp -m tcp --dport 80 -m state --state INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
iptables -t raw -I PREROUTING  -i $interface -p tcp -m tcp --syn --dport 8080 -j CT --notrack
iptables -t filter -A INPUT -i $interface -p tcp -m tcp --dport 8080 -m state --state INVALID,UNTRACKED -j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
iptables -t filter -A INPUT -i $interface -m state --state INVALID -j DROP

