// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
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

static inline int name_filter(struct sk_buff* skb)
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

static void update_data(struct queue_data *data, u64 len)
{
    data->total_pkt_len += len;
    data->num_pkt++;
    
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
    
    update_data(data, BPF_CORE_READ(skb, len));
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

    update_data(data, BPF_CORE_READ(skb, len));
    return 0;
}

char _license[] SEC("license") = "GPL";
