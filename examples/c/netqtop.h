#ifndef __NETQTOP_H
#define __NETQTOP_H

#define IFNAMSIZ      16
#define MAX_QUEUE_NUM 1024
#define ETH_P_IP      0x0800

union name_buf {
	char name[IFNAMSIZ];
	struct {
		__u64 hi;
		__u64 lo;
	} name_int;
};

struct queue_data {
	__u64 total_pkt_len; // Total bytes
	__u32 num_pkt; // Total packets
	__u32 size_64B; // Packet count by size
	__u32 size_512B;
	__u32 size_2K;
	__u32 size_16K;
	__u32 size_64K;
	__u32 syn_packets; // Added SYN packet counter
	/* Protocol counters */
	__u32 tcp_pkts; // TCP packets
	__u32 udp_pkts; // UDP packets
	__u32 icmp_pkts; // ICMP/ICMPv6 packets
	__u32 other_pkts; // Other protocols
};

#endif /* __NETQTOP_H */
