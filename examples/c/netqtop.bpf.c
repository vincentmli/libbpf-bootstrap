// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"
#include "netqtop.h"

/* Tracepoint structure for netif_receive_skb */
struct netif_receive_skb_tp {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	void *skbaddr;
	unsigned int len;
	__u16 queue_mapping;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, union name_buf);
} name_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_QUEUE_NUM);
	__type(key, u16);
	__type(value, struct queue_data);
} tx_q SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_QUEUE_NUM);
	__type(key, u16);
	__type(value, struct queue_data);
} rx_q SEC(".maps");

static inline int name_filter(struct sk_buff *skb)
{
	union name_buf real_devname = {};
	struct net_device *dev;

	BPF_CORE_READ_INTO(&dev, skb, dev);
	if (bpf_probe_read_kernel(&real_devname.name, IFNAMSIZ, dev->name))
		return 0;

	u32 key = 0;
	union name_buf *leaf = bpf_map_lookup_elem(&name_map, &key);
	if (!leaf)
		return 0;

	if (leaf->name_int.hi != real_devname.name_int.hi ||
	    leaf->name_int.lo != real_devname.name_int.lo)
		return 0;

	return 1;
}

static void update_protocol_stats(struct queue_data *data, struct sk_buff *skb)
{
	__u16 protocol = 0;
	__u8 ip_proto = 0;

	BPF_CORE_READ_INTO(&protocol, skb, protocol);

	// Check Ethernet type
	if (protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr iph;
		if (bpf_probe_read_kernel(&iph, sizeof(iph),
					  BPF_CORE_READ(skb, head) +
						  BPF_CORE_READ(skb, network_header)) == 0)
			ip_proto = iph.protocol;
	}

	// Count protocols
	switch (ip_proto) {
	case IPPROTO_TCP:
		data->tcp_pkts++;
		break;
	case IPPROTO_UDP:
		data->udp_pkts++;
		break;
	case IPPROTO_ICMP:
		data->icmp_pkts++;
		break;
	default:
		if (protocol != 0) // Don't count invalid packets
			data->other_pkts++;
	}
}

static __always_inline int is_syn_packet(struct sk_buff *skb)
{
	__u16 protocol;
	__u8 ip_proto;
	struct tcphdr tcph = {};

	if (bpf_probe_read_kernel(&tcph, sizeof(tcph),
				  BPF_CORE_READ(skb, head) +
					  BPF_CORE_READ(skb, transport_header)) == 0) {
		// Check if this is a SYN packet
		if (tcph.syn && !tcph.ack)
			return 1;
	}
	return 0;
}

static void update_data(struct queue_data *data, struct sk_buff *skb, bool is_rx)
{
	u64 len = BPF_CORE_READ(skb, len);

	data->total_pkt_len += len;
	data->num_pkt++;

	if (is_rx) {
		if (is_syn_packet(skb))
			data->syn_packets++;
	}

	if (len < 64)
		data->size_64B++;
	else if (len < 512)
		data->size_512B++;
	else if (len < 2048)
		data->size_2K++;
	else if (len < 16384)
		data->size_16K++;
	else if (len < 65536)
		data->size_64K++;

	update_protocol_stats(data, skb);
}

SEC("tracepoint/net/net_dev_start_xmit")
int net_dev_start_xmit(struct trace_event_raw_net_dev_start_xmit *args)
{
	struct sk_buff *skb;
	BPF_CORE_READ_INTO(&skb, args, skbaddr);

	if (!name_filter(skb))
		return 0;

	u16 qid = BPF_CORE_READ(skb, queue_mapping);
	struct queue_data newdata = {};

	struct queue_data *data = bpf_map_lookup_or_try_init(&tx_q, &qid, &newdata);
	if (!data)
		return 0;

	update_data(data, skb, false);
	return 0;
}

SEC("tracepoint/net/netif_receive_skb")
int netif_receive_skb(struct netif_receive_skb_tp *args)
{
	struct sk_buff *skb = (struct sk_buff *)args->skbaddr;

	if (!name_filter(skb))
		return 0;

	u16 qid = 0;
	u16 mapping = BPF_CORE_READ(skb, queue_mapping);
	if (mapping != 0xffff)
		qid = mapping;

	struct queue_data newdata = {};
	struct queue_data *data = bpf_map_lookup_or_try_init(&rx_q, &qid, &newdata);
	if (!data)
		return 0;

	update_data(data, skb, true);
	return 0;
}

char _license[] SEC("license") = "GPL";
