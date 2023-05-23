/*
 * Copyright (c) 2021, NLnet Labs. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifdef  DEBUG
#define DEBUG_PRINTK(...) bpf_printk(__VA_ARGS__)
#else
#define DEBUG_PRINTK(...)
#endif

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <asm/errno.h>

/* with vmlinux.h, define here to avoid the undefined error */
#define ETH_P_8021Q     0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD    0x88A8          /* 802.1ad Service VLAN         */

// do not use libc includes because this causes clang
// to include 32bit headers on 64bit ( only ) systems.
#define memcpy __builtin_memcpy

#ifndef __section
# define __section(NAME) __attribute__((section(NAME), used))
#endif
#ifndef __uint
# define __uint(name, val) int(*(name))[val]
#endif
#ifndef __type
#define __type(name, val) typeof(val) *(name)
#endif

#include "siphash4bpf.c"
#include "xdppacket.h"

struct meta_data {
	__u16 eth_proto;
	__u16 ip_pos;
	__u16 opt_pos;
	__u16 unused;
};

static volatile __u16 ratelimit = 10;
static volatile __u8 numcpus = 2;

struct ipv4_key {
	struct   bpf_lpm_trie_key lpm_key;
	__u8  ipv4[4];
};

struct {
	__uint(type,  BPF_MAP_TYPE_LPM_TRIE);
	__type(key,   struct ipv4_key);
	__type(value, __u64);
	__uint(max_entries, 10000);
//	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} exclude_v4_prefixes __section(".maps");

struct ipv6_key {
	struct   bpf_lpm_trie_key lpm_key;
	__u64 ipv6;
} __attribute__((packed));

struct {
	__uint(type,  BPF_MAP_TYPE_LPM_TRIE);
	__type(key,   struct ipv6_key);
	__type(value, __u64);
	__uint(max_entries, 10000);
//        __uint(pinning, LIBBPF_PIN_BY_NAME);
        __uint(map_flags, BPF_F_NO_PREALLOC);
} exclude_v6_prefixes __section(".maps");

/*
 *  Store the time frame
 */
struct bucket_time {
	__u64 start_time;
	__u64 n_packets;
};

struct {
	__uint(type,  BPF_MAP_TYPE_PERCPU_HASH);
	__type(key,   __u32);
	__type(value, struct bucket_time);
	__uint(max_entries, RRL_SIZE);
} state_map __section(".maps");

struct {
	__uint(type,  BPF_MAP_TYPE_PERCPU_HASH);
	__type(key,   sizeof(struct in6_addr));
	__type(value, struct bucket_time);
	__uint(max_entries, RRL_SIZE);
} state_map_v6 __section(".maps");


/** Copied from the kernel module of the base03-map-counter example of the
 ** XDP Hands-On Tutorial (see https://github.com/xdp-project/xdp-tutorial )
 *
 * LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

/*
 *  Store the VLAN header
 */
struct vlanhdr {
	__u16 tci;
	__u16 encap_proto;
};

/*
 *  Helper pointer to parse the incoming packets
 */
struct cursor {
	void *pos;
	void *end;
};

static __always_inline
void cursor_init(struct cursor *c, struct xdp_md *ctx)
{
	c->end = (void *)(long)ctx->data_end;
	c->pos = (void *)(long)ctx->data;
}

#define PARSE_FUNC_DECLARATION(STRUCT)			\
static __always_inline \
struct STRUCT *parse_ ## STRUCT (struct cursor *c)	\
{							\
	struct STRUCT *ret = c->pos;			\
	if (c->pos + sizeof(struct STRUCT) > c->end)	\
		return 0;				\
	c->pos += sizeof(struct STRUCT);		\
	return ret;					\
}

PARSE_FUNC_DECLARATION(ethhdr)
PARSE_FUNC_DECLARATION(vlanhdr)
PARSE_FUNC_DECLARATION(iphdr)
PARSE_FUNC_DECLARATION(ipv6hdr)
PARSE_FUNC_DECLARATION(udphdr)
PARSE_FUNC_DECLARATION(dnshdr)
PARSE_FUNC_DECLARATION(dns_qrr)
PARSE_FUNC_DECLARATION(dns_rr)
PARSE_FUNC_DECLARATION(option)

static __always_inline
struct ethhdr *parse_eth(struct cursor *c, __u16 *eth_proto)
{
	struct ethhdr  *eth;

	if (!(eth = parse_ethhdr(c)))
		return 0;

	*eth_proto = eth->h_proto;
	if (*eth_proto == __bpf_htons(ETH_P_8021Q)
	||  *eth_proto == __bpf_htons(ETH_P_8021AD)) {
		struct vlanhdr *vlan;

		if (!(vlan = parse_vlanhdr(c)))
			return 0;

		*eth_proto = vlan->encap_proto;
		if (*eth_proto == __bpf_htons(ETH_P_8021Q)
		||  *eth_proto == __bpf_htons(ETH_P_8021AD)) {
			if (!(vlan = parse_vlanhdr(c)))
				return 0;

			*eth_proto = vlan->encap_proto;
		}
	}
	return eth;
}

static  inline
__u8 *skip_dname(struct cursor *c)
{
        __u8 *dname = c->pos;
	__u8 i;

        for (i = 0; i < 128; i++) { /* Maximum 128 labels */
                __u8 o;

                if (c->pos + 1 > c->end)
                        return 0;

                o = *(__u8 *)c->pos;
                if ((o & 0xC0) == 0xC0) {
                        /* Compression label is last label of dname. */
                        c->pos += 2;
                        return dname;

                } else if (o > 63 || c->pos + o + 1 > c->end)
                        /* Unknown label type */
                        return 0;

                c->pos += o + 1;
                if (!o)
                        return dname;
        }
        return 0;
}

static __always_inline enum xdp_action
do_rate_limit(struct udphdr *udp, struct dnshdr *dns, struct bucket_time *b)
{
	// increment number of packets
	b->n_packets++;

	// get the current and elapsed time
	__u64 now = bpf_ktime_get_ns();
	__u64 elapsed = now - b->start_time;

	// make sure the elapsed time is set and not outside of the frame
	if (b->start_time == 0 || elapsed >= FRAME_SIZE)
	{
		// start new time frame
		b->start_time = now;
		b->n_packets = 0;
	}

	if (b->n_packets < ratelimit / numcpus)
		return XDP_PASS;

#if  RRL_SLIP == 0
	return XDP_DROP;
#else
# if RRL_SLIP >  1
	if (b->n_packets % RRL_SLIP)
		return XDP_DROP;
# endif
	//save the old header values
	__u16 old_val = dns->flags.as_value;

	// change the DNS flags
	dns->flags.as_bits_and_pieces.ad = 0;
	dns->flags.as_bits_and_pieces.qr = 1;
	dns->flags.as_bits_and_pieces.tc = 1;

	// change the UDP destination to the source
	udp->dest   = udp->source;
	udp->source = __bpf_htons(DNS_PORT);

	// calculate and write the new checksum
	update_checksum(&udp->check, old_val, dns->flags.as_value);

	// bounce
	return XDP_TX;
#endif
}

SEC("xdp")
int xdp_do_rate_limit_ipv6(struct xdp_md *ctx)
{
	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct ipv6hdr   *ipv6;
	struct in6_addr   ipv6_addr;
	struct udphdr    *udp;
	struct dnshdr    *dns;

	DEBUG_PRINTK("xdp_do_rate_limit_ipv6\n");

	cursor_init(&c, ctx);
	if ((void *)(md + 1) > c.pos || md->ip_pos > 24)
		return XDP_ABORTED;
	c.pos += md->ip_pos;

	if (!(ipv6 = parse_ipv6hdr(&c)) || md->opt_pos > 4096
	||  !(udp = parse_udphdr(&c)) || udp->dest != __bpf_htons(DNS_PORT)
	||  !(dns = parse_dnshdr(&c)))
		return XDP_ABORTED;

	ipv6_addr = ipv6->saddr;
 	// get the rrl bucket from the map by IPv6 address
#if     RRL_IPv6_PREFIX_LEN == 128
#elif   RRL_IPv6_PREFIX_LEN >   96
	ipv6_addr.in6_u.u6_addr32[3] &= RRL_IPv6_MASK;
#else
	ipv6_addr.in6_u.u6_addr32[3] = 0;
# if    RRL_IPv6_PREFIX_LEN ==  96
# elif  RRL_IPv6_PREFIX_LEN >   64
	ipv6_addr.in6_u.u6_addr32[2] &= RRL_IPv6_MASK;
# else
	ipv6_addr.in6_u.u6_addr32[2] = 0;
#  if   RRL_IPv6_PREFIX_LEN ==  64
#  elif RRL_IPv6_PREFIX_LEN >   32
	ipv6_addr.in6_u.u6_addr32[1] &= RRL_IPv6_MASK;
#  else
	ipv6_addr.in6_u.u6_addr32[1] = 0;
#   if  RRL_IPv6_PREFIX_LEN ==   0
	ipv6_addr.in6_u.u6_addr32[0] = 0;
#   elif RRL_IPv6_PREFIX_LEN <  32
	ipv6_addr.in6_u.u6_addr32[0] &= RRL_IPv6_MASK;
#   endif
#  endif
# endif
#endif
 	struct bucket_time *b = bpf_map_lookup_elem(&state_map_v6, &ipv6_addr);

 	// did we see this IPv6 address before?
	if (b)
		return do_rate_limit(udp, dns, b);

	// create new starting bucket for this key
	struct bucket_time new_bucket;
	new_bucket.start_time = bpf_ktime_get_ns();
	new_bucket.n_packets = 0;

	// store the bucket and pass the packet
	bpf_map_update_elem(&state_map_v6, &ipv6_addr, &new_bucket, BPF_ANY);
	return XDP_PASS;
}

SEC("xdp")
int xdp_do_rate_limit_ipv4(struct xdp_md *ctx)
{
	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct iphdr     *ipv4;
	__u32          ipv4_addr;
	struct udphdr    *udp;
	struct dnshdr    *dns;

	DEBUG_PRINTK("xdp_do_rate_limit_ipv4\n");

	cursor_init(&c, ctx);
	if ((void *)(md + 1) > c.pos || md->ip_pos > 24)
		return XDP_ABORTED;
	c.pos += md->ip_pos;

	if (!(ipv4 = parse_iphdr(&c)) || md->opt_pos > 4096
	||  !(udp = parse_udphdr(&c)) || udp->dest != __bpf_htons(DNS_PORT)
	||  !(dns = parse_dnshdr(&c)))
		return XDP_ABORTED;

	// get the rrl bucket from the map by IPv4 address
#if   RRL_IPv4_PREFIX_LEN == 32
#elif RRL_IPv4_PREFIX_LEN ==  0
	ipv4_addr = 0;
#else
	ipv4_addr = ipv4->saddr & RRL_IPv4_MASK;
#endif
	struct bucket_time *b = bpf_map_lookup_elem(&state_map, &ipv4_addr);

	// did we see this IPv4 address before?
	if (b)
		return do_rate_limit(udp, dns, b);

	// create new starting bucket for this key
	struct bucket_time new_bucket;
	new_bucket.start_time = bpf_ktime_get_ns();
	new_bucket.n_packets = 0;

	// store the bucket and pass the packet
	bpf_map_update_elem(&state_map, &ipv4_addr, &new_bucket, BPF_ANY);
	return XDP_PASS;
}

struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 3);
        __uint(key_size, sizeof(__u32));
        __uint(value_size, sizeof(__u32));
        __array(values, int (void *));
} jmp_rate_table SEC(".maps") = {
        .values = {
                [DO_RATE_LIMIT_IPV6] = (void *)&xdp_do_rate_limit_ipv6,
                [DO_RATE_LIMIT_IPV4] = (void *)&xdp_do_rate_limit_ipv4,
        },
};

static __always_inline
int cookie_verify_ipv6(struct cursor *c, struct ipv6hdr *ipv6)
{
	__u8  input[32];
	__u64 hash;

	memcpy(input, c->pos, 16);
	memcpy(input + 16, &ipv6->saddr, 16);
	siphash_ipv6(input, (__u8 *)&hash);
	return hash == ((__u64 *)c->pos)[2];
}

SEC("xdp")
int xdp_cookie_verify_ipv6(struct xdp_md *ctx)
{
	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct ipv6hdr   *ipv6;
	struct dns_rr    *opt_rr;
	__u16          rdata_len;
	__u8           i;

	cursor_init(&c, ctx);
	if ((void *)(md + 1) > c.pos || md->ip_pos > 24)
		return XDP_ABORTED;
	c.pos += md->ip_pos;

	if (!(ipv6 = parse_ipv6hdr(&c)) || md->opt_pos > 4096)
		return XDP_ABORTED;
	c.pos += md->opt_pos;

	if (!(opt_rr = parse_dns_rr(&c))
	||    opt_rr->type != __bpf_htons(RR_TYPE_OPT))
		return XDP_ABORTED;

	rdata_len = __bpf_ntohs(opt_rr->rdata_len);
	for (i = 0; i < 10 && rdata_len >= 28; i++) {
		struct option *opt;
		__u16       opt_len;

		if (!(opt = parse_option(&c)))
			return XDP_ABORTED;

		rdata_len -= 4;
		opt_len = __bpf_ntohs(opt->len);
		if (opt->code == __bpf_htons(OPT_CODE_COOKIE)) {
			if (opt_len == 24 && c.pos + 24 <= c.end
			&&  cookie_verify_ipv6(&c, ipv6)) {
				/* Cookie match!
				 * Packet may go staight up to the DNS service
				 */
				DEBUG_PRINTK("IPv6 valid cookie\n");
				return XDP_PASS;
			}
			/* Just a client cookie or a bad cookie
			 * break to go to rate limiting
			 */
			DEBUG_PRINTK("IPv6 bad cookie\n");
			break;
		}
		if (opt_len > 1500 || opt_len > rdata_len
		||  c.pos + opt_len > c.end)
			return XDP_ABORTED;

		rdata_len -= opt_len;
		c.pos += opt_len;
	}
	bpf_tail_call(ctx, &jmp_rate_table, DO_RATE_LIMIT_IPV6);
	return XDP_PASS;
}


static __always_inline
int cookie_verify_ipv4(struct cursor *c, struct iphdr *ipv4)
{
	__u8  input[20];
	__u64 hash;

	memcpy(input, c->pos, 16);
	memcpy(input + 16, &ipv4->saddr, 4);
	siphash_ipv4(input, (__u8 *)&hash);
	return hash == ((__u64 *)c->pos)[2];
}

SEC("xdp")
int xdp_cookie_verify_ipv4(struct xdp_md *ctx)
{
	struct cursor     c;
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct iphdr     *ipv4;
	struct dns_rr    *opt_rr;
	__u16          rdata_len;
	__u8           i;

	cursor_init(&c, ctx);
	if ((void *)(md + 1) > c.pos || md->ip_pos > 24)
		return XDP_ABORTED;
	c.pos += md->ip_pos;

	if (!(ipv4 = parse_iphdr(&c)) || md->opt_pos > 4096)
		return XDP_ABORTED;
	c.pos += md->opt_pos;

	if (!(opt_rr = parse_dns_rr(&c))
	||    opt_rr->type != __bpf_htons(RR_TYPE_OPT))
		return XDP_ABORTED;

	rdata_len = __bpf_ntohs(opt_rr->rdata_len);
	for (i = 0; i < 10 && rdata_len >= 28; i++) {
		struct option *opt;
		__u16       opt_len;

		if (!(opt = parse_option(&c)))
			return XDP_ABORTED;

		rdata_len -= 4;
		opt_len = __bpf_ntohs(opt->len);
		if (opt->code == __bpf_htons(OPT_CODE_COOKIE)) {
			if (opt_len == 24 && c.pos + 24 <= c.end
			&&  cookie_verify_ipv4(&c, ipv4)) {
				/* Cookie match!
				 * Packet may go staight up to the DNS service
				 */
				DEBUG_PRINTK("IPv4 valid cookie\n");
				return XDP_PASS;
			}
			/* Just a client cookie or a bad cookie
			 * break to go to rate limiting
			 */
			DEBUG_PRINTK("IPv4 bad cookie\n");
			break;
		}
		if (opt_len > 1500 || opt_len > rdata_len
		||  c.pos + opt_len > c.end)
			return XDP_ABORTED;

		rdata_len -= opt_len;
		c.pos += opt_len;
	}
	bpf_tail_call(ctx, &jmp_rate_table, DO_RATE_LIMIT_IPV4);
	return XDP_PASS;
}

struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 3);
        __uint(key_size, sizeof(__u32));
        __uint(value_size, sizeof(__u32));
        __array(values, int (void *));
} jmp_cookie_table SEC(".maps") = {
        .values = {
                [COOKIE_VERIFY_IPv6] = (void *)&xdp_cookie_verify_ipv6,
                [COOKIE_VERIFY_IPv4] = (void *)&xdp_cookie_verify_ipv4,
        },
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 2);
} values SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u16);
	__uint(max_entries, MAX_ALLOWED_PORTS);
} allowed_ports SEC(".maps");

/* Some symbols defined in net/netfilter/nf_conntrack_bpf.c are unavailable in
 * vmlinux.h if CONFIG_NF_CONNTRACK=m, so they are redefined locally.
 */

struct bpf_ct_opts___local {
	s32 netns_id;
	s32 error;
	u8 l4proto;
	u8 dir;
	u8 reserved[2];
} __attribute__((preserve_access_index));

#define BPF_F_CURRENT_NETNS (-1)

extern struct nf_conn *bpf_xdp_ct_lookup(struct xdp_md *xdp_ctx,
					 struct bpf_sock_tuple *bpf_tuple,
					 __u32 len_tuple,
					 struct bpf_ct_opts___local *opts,
					 __u32 len_opts) __ksym;

extern struct nf_conn *bpf_skb_ct_lookup(struct __sk_buff *skb_ctx,
					 struct bpf_sock_tuple *bpf_tuple,
					 u32 len_tuple,
					 struct bpf_ct_opts___local *opts,
					 u32 len_opts) __ksym;

extern void bpf_ct_release(struct nf_conn *ct) __ksym;

static __always_inline void swap_eth_addr(__u8 *a, __u8 *b)
{
	__u8 tmp[ETH_ALEN];

	__builtin_memcpy(tmp, a, ETH_ALEN);
	__builtin_memcpy(a, b, ETH_ALEN);
	__builtin_memcpy(b, tmp, ETH_ALEN);
}

static __always_inline __u16 csum_fold(__u32 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__u16)~csum;
}

static __always_inline __u16 csum_tcpudp_magic(__be32 saddr, __be32 daddr,
					       __u32 len, __u8 proto,
					       __u32 csum)
{
	__u64 s = csum;

	s += (__u32)saddr;
	s += (__u32)daddr;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	s += proto + len;
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	s += (proto + len) << 8;
#else
#error Unknown endian
#endif
	s = (s & 0xffffffff) + (s >> 32);
	s = (s & 0xffffffff) + (s >> 32);

	return csum_fold((__u32)s);
}

static __always_inline __u16 csum_ipv6_magic(const struct in6_addr *saddr,
					     const struct in6_addr *daddr,
					     __u32 len, __u8 proto, __u32 csum)
{
	__u64 sum = csum;
	int i;

#pragma unroll
	for (i = 0; i < 4; i++)
		sum += (__u32)saddr->in6_u.u6_addr32[i];

#pragma unroll
	for (i = 0; i < 4; i++)
		sum += (__u32)daddr->in6_u.u6_addr32[i];

	/* Don't combine additions to avoid 32-bit overflow. */
	sum += bpf_htonl(len);
	sum += bpf_htonl(proto);

	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffffffff) + (sum >> 32);

	return csum_fold((__u32)sum);
}

static __always_inline __u64 tcp_clock_ns(void)
{
	return bpf_ktime_get_ns();
}

static __always_inline __u32 tcp_ns_to_ts(__u64 ns)
{
	return ns / (NSEC_PER_SEC / TCP_TS_HZ);
}

static __always_inline __u32 tcp_time_stamp_raw(void)
{
	return tcp_ns_to_ts(tcp_clock_ns());
}

struct tcpopt_context {
	__u8 *ptr;
	__u8 *end;
	void *data_end;
	__be32 *tsecr;
	__u8 wscale;
	bool option_timestamp;
	bool option_sack;
};

static int tscookie_tcpopt_parse(struct tcpopt_context *ctx)
{
	__u8 opcode, opsize;

	if (ctx->ptr >= ctx->end)
		return 1;
	if (ctx->ptr >= ctx->data_end)
		return 1;

	opcode = ctx->ptr[0];

	if (opcode == TCPOPT_EOL)
		return 1;
	if (opcode == TCPOPT_NOP) {
		++ctx->ptr;
		return 0;
	}

	if (ctx->ptr + 1 >= ctx->end)
		return 1;
	if (ctx->ptr + 1 >= ctx->data_end)
		return 1;
	opsize = ctx->ptr[1];
	if (opsize < 2)
		return 1;

	if (ctx->ptr + opsize > ctx->end)
		return 1;

	switch (opcode) {
	case TCPOPT_WINDOW:
		if (opsize == TCPOLEN_WINDOW && ctx->ptr + TCPOLEN_WINDOW <= ctx->data_end)
			ctx->wscale = ctx->ptr[2] < TCP_MAX_WSCALE ? ctx->ptr[2] : TCP_MAX_WSCALE;
		break;
	case TCPOPT_TIMESTAMP:
		if (opsize == TCPOLEN_TIMESTAMP && ctx->ptr + TCPOLEN_TIMESTAMP <= ctx->data_end) {
			ctx->option_timestamp = true;
			/* Client's tsval becomes our tsecr. */
			*ctx->tsecr = get_unaligned((__be32 *)(ctx->ptr + 2));
		}
		break;
	case TCPOPT_SACK_PERM:
		if (opsize == TCPOLEN_SACK_PERM)
			ctx->option_sack = true;
		break;
	}

	ctx->ptr += opsize;

	return 0;
}

static int tscookie_tcpopt_parse_batch(__u32 index, void *context)
{
	int i;

	for (i = 0; i < 7; i++)
		if (tscookie_tcpopt_parse(context))
			return 1;
	return 0;
}

static __always_inline bool tscookie_init(struct tcphdr *tcp_header,
					  __u16 tcp_len, __be32 *tsval,
					  __be32 *tsecr, void *data_end)
{
	struct tcpopt_context loop_ctx = {
		.ptr = (__u8 *)(tcp_header + 1),
		.end = (__u8 *)tcp_header + tcp_len,
		.data_end = data_end,
		.tsecr = tsecr,
		.wscale = TS_OPT_WSCALE_MASK,
		.option_timestamp = false,
		.option_sack = false,
	};
	u32 cookie;

	bpf_loop(6, tscookie_tcpopt_parse_batch, &loop_ctx, 0);

	if (!loop_ctx.option_timestamp)
		return false;

	cookie = tcp_time_stamp_raw() & ~TSMASK;
	cookie |= loop_ctx.wscale & TS_OPT_WSCALE_MASK;
	if (loop_ctx.option_sack)
		cookie |= TS_OPT_SACK;
	if (tcp_header->ece && tcp_header->cwr)
		cookie |= TS_OPT_ECN;
	*tsval = bpf_htonl(cookie);

	return true;
}

static __always_inline void values_get_tcpipopts(__u16 *mss, __u8 *wscale,
						 __u8 *ttl, bool ipv6)
{
	__u32 key = 0;
	__u64 *value;

	value = bpf_map_lookup_elem(&values, &key);
	if (value && *value != 0) {
		if (ipv6)
			*mss = (*value >> 32) & 0xffff;
		else
			*mss = *value & 0xffff;
		*wscale = (*value >> 16) & 0xf;
		*ttl = (*value >> 24) & 0xff;
		return;
	}

	*mss = ipv6 ? DEFAULT_MSS6 : DEFAULT_MSS4;
	*wscale = DEFAULT_WSCALE;
	*ttl = DEFAULT_TTL;
}

static __always_inline void values_inc_synacks(void)
{
	__u32 key = 1;
	__u64 *value;

	value = bpf_map_lookup_elem(&values, &key);
	if (value)
		__sync_fetch_and_add(value, 1);
}

static __always_inline bool check_port_allowed(__u16 port)
{
	__u32 i;

	for (i = 0; i < MAX_ALLOWED_PORTS; i++) {
		__u32 key = i;
		__u16 *value;

		value = bpf_map_lookup_elem(&allowed_ports, &key);

		if (!value)
			break;
		/* 0 is a terminator value. Check it first to avoid matching on
		 * a forbidden port == 0 and returning true.
		 */
		if (*value == 0)
			break;

		if (*value == port)
			return true;
	}

	return false;
}

struct header_pointers {
	struct ethhdr *eth;
	struct iphdr *ipv4;
	struct ipv6hdr *ipv6;
	struct tcphdr *tcp;
	__u16 tcp_len;
};

static __always_inline int tcp_dissect(void *data, void *data_end,
				       struct header_pointers *hdr)
{
	hdr->eth = data;
	if (hdr->eth + 1 > data_end)
		return XDP_DROP;

	switch (bpf_ntohs(hdr->eth->h_proto)) {
	case ETH_P_IP:
		hdr->ipv6 = NULL;

		hdr->ipv4 = (void *)hdr->eth + sizeof(*hdr->eth);
		if (hdr->ipv4 + 1 > data_end)
			return XDP_DROP;
		if (hdr->ipv4->ihl * 4 < sizeof(*hdr->ipv4))
			return XDP_DROP;
		if (hdr->ipv4->version != 4)
			return XDP_DROP;

		if (hdr->ipv4->protocol != IPPROTO_TCP)
			return XDP_PASS;

		hdr->tcp = (void *)hdr->ipv4 + hdr->ipv4->ihl * 4;
		break;
	case ETH_P_IPV6:
		hdr->ipv4 = NULL;

		hdr->ipv6 = (void *)hdr->eth + sizeof(*hdr->eth);
		if (hdr->ipv6 + 1 > data_end)
			return XDP_DROP;
		if (hdr->ipv6->version != 6)
			return XDP_DROP;

		/* XXX: Extension headers are not supported and could circumvent
		 * XDP SYN flood protection.
		 */
		if (hdr->ipv6->nexthdr != NEXTHDR_TCP)
			return XDP_PASS;

		hdr->tcp = (void *)hdr->ipv6 + sizeof(*hdr->ipv6);
		break;
	default:
		/* XXX: VLANs will circumvent XDP SYN flood protection. */
		return XDP_PASS;
	}

	if (hdr->tcp + 1 > data_end)
		return XDP_DROP;
	hdr->tcp_len = hdr->tcp->doff * 4;
	if (hdr->tcp_len < sizeof(*hdr->tcp))
		return XDP_DROP;

	return XDP_TX;
}

static __always_inline int tcp_lookup(void *ctx, struct header_pointers *hdr, bool xdp)
{
	struct bpf_ct_opts___local ct_lookup_opts = {
		.netns_id = BPF_F_CURRENT_NETNS,
		.l4proto = IPPROTO_TCP,
	};
	struct bpf_sock_tuple tup = {};
	struct nf_conn *ct;
	__u32 tup_size;

	if (hdr->ipv4) {
		/* TCP doesn't normally use fragments, and XDP can't reassemble
		 * them.
		 */
		if ((hdr->ipv4->frag_off & bpf_htons(IP_DF | IP_MF | IP_OFFSET)) != bpf_htons(IP_DF))
			return XDP_DROP;

		tup.ipv4.saddr = hdr->ipv4->saddr;
		tup.ipv4.daddr = hdr->ipv4->daddr;
		tup.ipv4.sport = hdr->tcp->source;
		tup.ipv4.dport = hdr->tcp->dest;
		tup_size = sizeof(tup.ipv4);
	} else if (hdr->ipv6) {
		__builtin_memcpy(tup.ipv6.saddr, &hdr->ipv6->saddr, sizeof(tup.ipv6.saddr));
		__builtin_memcpy(tup.ipv6.daddr, &hdr->ipv6->daddr, sizeof(tup.ipv6.daddr));
		tup.ipv6.sport = hdr->tcp->source;
		tup.ipv6.dport = hdr->tcp->dest;
		tup_size = sizeof(tup.ipv6);
	} else {
		/* The verifier can't track that either ipv4 or ipv6 is not
		 * NULL.
		 */
		return XDP_ABORTED;
	}
	if (xdp)
		ct = bpf_xdp_ct_lookup(ctx, &tup, tup_size, &ct_lookup_opts, sizeof(ct_lookup_opts));
	else
		ct = bpf_skb_ct_lookup(ctx, &tup, tup_size, &ct_lookup_opts, sizeof(ct_lookup_opts));
	if (ct) {
		unsigned long status = ct->status;

		bpf_ct_release(ct);
		if (status & IPS_CONFIRMED_BIT)
			return XDP_PASS;
	} else if (ct_lookup_opts.error != -ENOENT) {
		return XDP_ABORTED;
	}

	/* error == -ENOENT || !(status & IPS_CONFIRMED_BIT) */
	return XDP_TX;
}

static __always_inline __u8 tcp_mkoptions(__be32 *buf, __be32 *tsopt, __u16 mss,
					  __u8 wscale)
{
	__be32 *start = buf;

	*buf++ = bpf_htonl((TCPOPT_MSS << 24) | (TCPOLEN_MSS << 16) | mss);

	if (!tsopt)
		return buf - start;

	if (tsopt[0] & bpf_htonl(1 << 4))
		*buf++ = bpf_htonl((TCPOPT_SACK_PERM << 24) |
				   (TCPOLEN_SACK_PERM << 16) |
				   (TCPOPT_TIMESTAMP << 8) |
				   TCPOLEN_TIMESTAMP);
	else
		*buf++ = bpf_htonl((TCPOPT_NOP << 24) |
				   (TCPOPT_NOP << 16) |
				   (TCPOPT_TIMESTAMP << 8) |
				   TCPOLEN_TIMESTAMP);
	*buf++ = tsopt[0];
	*buf++ = tsopt[1];

	if ((tsopt[0] & bpf_htonl(0xf)) != bpf_htonl(0xf))
		*buf++ = bpf_htonl((TCPOPT_NOP << 24) |
				   (TCPOPT_WINDOW << 16) |
				   (TCPOLEN_WINDOW << 8) |
				   wscale);

	return buf - start;
}

static __always_inline void tcp_gen_synack(struct tcphdr *tcp_header,
					   __u32 cookie, __be32 *tsopt,
					   __u16 mss, __u8 wscale)
{
	void *tcp_options;

	tcp_flag_word(tcp_header) = TCP_FLAG_SYN | TCP_FLAG_ACK;
	if (tsopt && (tsopt[0] & bpf_htonl(1 << 5)))
		tcp_flag_word(tcp_header) |= TCP_FLAG_ECE;
	tcp_header->doff = 5; /* doff is part of tcp_flag_word. */
	swap(tcp_header->source, tcp_header->dest);
	tcp_header->ack_seq = bpf_htonl(bpf_ntohl(tcp_header->seq) + 1);
	tcp_header->seq = bpf_htonl(cookie);
	tcp_header->window = 0;
	tcp_header->urg_ptr = 0;
	tcp_header->check = 0; /* Calculate checksum later. */

	tcp_options = (void *)(tcp_header + 1);
	tcp_header->doff += tcp_mkoptions(tcp_options, tsopt, mss, wscale);
}

static __always_inline void tcpv4_gen_synack(struct header_pointers *hdr,
					     __u32 cookie, __be32 *tsopt)
{
	__u8 wscale;
	__u16 mss;
	__u8 ttl;

	values_get_tcpipopts(&mss, &wscale, &ttl, false);

	swap_eth_addr(hdr->eth->h_source, hdr->eth->h_dest);

	swap(hdr->ipv4->saddr, hdr->ipv4->daddr);
	hdr->ipv4->check = 0; /* Calculate checksum later. */
	hdr->ipv4->tos = 0;
	hdr->ipv4->id = 0;
	hdr->ipv4->ttl = ttl;

	tcp_gen_synack(hdr->tcp, cookie, tsopt, mss, wscale);

	hdr->tcp_len = hdr->tcp->doff * 4;
	hdr->ipv4->tot_len = bpf_htons(sizeof(*hdr->ipv4) + hdr->tcp_len);
}

static __always_inline void tcpv6_gen_synack(struct header_pointers *hdr,
					     __u32 cookie, __be32 *tsopt)
{
	__u8 wscale;
	__u16 mss;
	__u8 ttl;

	values_get_tcpipopts(&mss, &wscale, &ttl, true);

	swap_eth_addr(hdr->eth->h_source, hdr->eth->h_dest);

	swap(hdr->ipv6->saddr, hdr->ipv6->daddr);
	*(__be32 *)hdr->ipv6 = bpf_htonl(0x60000000);
	hdr->ipv6->hop_limit = ttl;

	tcp_gen_synack(hdr->tcp, cookie, tsopt, mss, wscale);

	hdr->tcp_len = hdr->tcp->doff * 4;
	hdr->ipv6->payload_len = bpf_htons(hdr->tcp_len);
}

static __always_inline int syncookie_handle_syn(struct header_pointers *hdr,
						void *ctx,
						void *data, void *data_end,
						bool xdp)
{
	__u32 old_pkt_size, new_pkt_size;
	/* Unlike clang 10, clang 11 and 12 generate code that doesn't pass the
	 * BPF verifier if tsopt is not volatile. Volatile forces it to store
	 * the pointer value and use it directly, otherwise tcp_mkoptions is
	 * (mis)compiled like this:
	 *   if (!tsopt)
	 *       return buf - start;
	 *   reg = stored_return_value_of_tscookie_init;
	 *   if (reg)
	 *       tsopt = tsopt_buf;
	 *   else
	 *       tsopt = NULL;
	 *   ...
	 *   *buf++ = tsopt[1];
	 * It creates a dead branch where tsopt is assigned NULL, but the
	 * verifier can't prove it's dead and blocks the program.
	 */
	__be32 * volatile tsopt = NULL;
	__be32 tsopt_buf[2] = {};
	__u16 ip_len;
	__u32 cookie;
	__s64 value;

	/* Checksum is not yet verified, but both checksum failure and TCP
	 * header checks return XDP_DROP, so the order doesn't matter.
	 */
	if (hdr->tcp->fin || hdr->tcp->rst)
		return XDP_DROP;

	/* Issue SYN cookies on allowed ports, drop SYN packets on blocked
	 * ports.
	 */
	if (!check_port_allowed(bpf_ntohs(hdr->tcp->dest)))
		return XDP_DROP;

	if (hdr->ipv4) {
		/* Check the IPv4 and TCP checksums before creating a SYNACK. */
		value = bpf_csum_diff(0, 0, (void *)hdr->ipv4, hdr->ipv4->ihl * 4, 0);
		if (value < 0)
			return XDP_ABORTED;
		if (csum_fold(value) != 0)
			return XDP_DROP; /* Bad IPv4 checksum. */

		value = bpf_csum_diff(0, 0, (void *)hdr->tcp, hdr->tcp_len, 0);
		if (value < 0)
			return XDP_ABORTED;
		if (csum_tcpudp_magic(hdr->ipv4->saddr, hdr->ipv4->daddr,
				      hdr->tcp_len, IPPROTO_TCP, value) != 0)
			return XDP_DROP; /* Bad TCP checksum. */

		ip_len = sizeof(*hdr->ipv4);

		value = bpf_tcp_raw_gen_syncookie_ipv4(hdr->ipv4, hdr->tcp,
						       hdr->tcp_len);
	} else if (hdr->ipv6) {
		/* Check the TCP checksum before creating a SYNACK. */
		value = bpf_csum_diff(0, 0, (void *)hdr->tcp, hdr->tcp_len, 0);
		if (value < 0)
			return XDP_ABORTED;
		if (csum_ipv6_magic(&hdr->ipv6->saddr, &hdr->ipv6->daddr,
				    hdr->tcp_len, IPPROTO_TCP, value) != 0)
			return XDP_DROP; /* Bad TCP checksum. */

		ip_len = sizeof(*hdr->ipv6);

		value = bpf_tcp_raw_gen_syncookie_ipv6(hdr->ipv6, hdr->tcp,
						       hdr->tcp_len);
	} else {
		return XDP_ABORTED;
	}

	if (value < 0)
		return XDP_ABORTED;
	cookie = (__u32)value;

	if (tscookie_init((void *)hdr->tcp, hdr->tcp_len,
			  &tsopt_buf[0], &tsopt_buf[1], data_end))
		tsopt = tsopt_buf;

	/* Check that there is enough space for a SYNACK. It also covers
	 * the check that the destination of the __builtin_memmove below
	 * doesn't overflow.
	 */
	if (data + sizeof(*hdr->eth) + ip_len + TCP_MAXLEN > data_end)
		return XDP_ABORTED;

	if (hdr->ipv4) {
		if (hdr->ipv4->ihl * 4 > sizeof(*hdr->ipv4)) {
			struct tcphdr *new_tcp_header;

			new_tcp_header = data + sizeof(*hdr->eth) + sizeof(*hdr->ipv4);
			__builtin_memmove(new_tcp_header, hdr->tcp, sizeof(*hdr->tcp));
			hdr->tcp = new_tcp_header;

			hdr->ipv4->ihl = sizeof(*hdr->ipv4) / 4;
		}

		tcpv4_gen_synack(hdr, cookie, tsopt);
	} else if (hdr->ipv6) {
		tcpv6_gen_synack(hdr, cookie, tsopt);
	} else {
		return XDP_ABORTED;
	}

	/* Recalculate checksums. */
	hdr->tcp->check = 0;
	value = bpf_csum_diff(0, 0, (void *)hdr->tcp, hdr->tcp_len, 0);
	if (value < 0)
		return XDP_ABORTED;
	if (hdr->ipv4) {
		hdr->tcp->check = csum_tcpudp_magic(hdr->ipv4->saddr,
						    hdr->ipv4->daddr,
						    hdr->tcp_len,
						    IPPROTO_TCP,
						    value);

		hdr->ipv4->check = 0;
		value = bpf_csum_diff(0, 0, (void *)hdr->ipv4, sizeof(*hdr->ipv4), 0);
		if (value < 0)
			return XDP_ABORTED;
		hdr->ipv4->check = csum_fold(value);
	} else if (hdr->ipv6) {
		hdr->tcp->check = csum_ipv6_magic(&hdr->ipv6->saddr,
						  &hdr->ipv6->daddr,
						  hdr->tcp_len,
						  IPPROTO_TCP,
						  value);
	} else {
		return XDP_ABORTED;
	}

	/* Set the new packet size. */
	old_pkt_size = data_end - data;
	new_pkt_size = sizeof(*hdr->eth) + ip_len + hdr->tcp->doff * 4;
	if (xdp) {
		if (bpf_xdp_adjust_tail(ctx, new_pkt_size - old_pkt_size))
			return XDP_ABORTED;
	} else {
		if (bpf_skb_change_tail(ctx, new_pkt_size, 0))
			return XDP_ABORTED;
	}

	values_inc_synacks();

	return XDP_TX;
}

static __always_inline int syncookie_handle_ack(struct header_pointers *hdr)
{
	int err;

	if (hdr->tcp->rst)
		return XDP_DROP;

	if (hdr->ipv4)
		err = bpf_tcp_raw_check_syncookie_ipv4(hdr->ipv4, hdr->tcp);
	else if (hdr->ipv6)
		err = bpf_tcp_raw_check_syncookie_ipv6(hdr->ipv6, hdr->tcp);
	else
		return XDP_ABORTED;
	if (err)
		return XDP_DROP;

	return XDP_PASS;
}

static __always_inline int syncookie_part1(void *ctx, void *data, void *data_end,
					   struct header_pointers *hdr, bool xdp)
{
	int ret;

	ret = tcp_dissect(data, data_end, hdr);
	if (ret != XDP_TX)
		return ret;

	ret = tcp_lookup(ctx, hdr, xdp);
	if (ret != XDP_TX)
		return ret;

	/* Packet is TCP and doesn't belong to an established connection. */

	if ((hdr->tcp->syn ^ hdr->tcp->ack) != 1)
		return XDP_DROP;

	/* Grow the TCP header to TCP_MAXLEN to be able to pass any hdr->tcp_len
	 * to bpf_tcp_raw_gen_syncookie_ipv{4,6} and pass the verifier.
	 */
	if (xdp) {
		if (bpf_xdp_adjust_tail(ctx, TCP_MAXLEN - hdr->tcp_len))
			return XDP_ABORTED;
	} else {
		/* Without volatile the verifier throws this error:
		 * R9 32-bit pointer arithmetic prohibited
		 */
		volatile u64 old_len = data_end - data;

		if (bpf_skb_change_tail(ctx, old_len + TCP_MAXLEN - hdr->tcp_len, 0))
			return XDP_ABORTED;
	}

	return XDP_TX;
}

static __always_inline int syncookie_part2(void *ctx, void *data, void *data_end,
					   struct header_pointers *hdr, bool xdp)
{
	if (hdr->ipv4) {
		hdr->eth = data;
		hdr->ipv4 = (void *)hdr->eth + sizeof(*hdr->eth);
		/* IPV4_MAXLEN is needed when calculating checksum.
		 * At least sizeof(struct iphdr) is needed here to access ihl.
		 */
		if ((void *)hdr->ipv4 + IPV4_MAXLEN > data_end)
			return XDP_ABORTED;
		hdr->tcp = (void *)hdr->ipv4 + hdr->ipv4->ihl * 4;
	} else if (hdr->ipv6) {
		hdr->eth = data;
		hdr->ipv6 = (void *)hdr->eth + sizeof(*hdr->eth);
		hdr->tcp = (void *)hdr->ipv6 + sizeof(*hdr->ipv6);
	} else {
		return XDP_ABORTED;
	}

	if ((void *)hdr->tcp + TCP_MAXLEN > data_end)
		return XDP_ABORTED;

	/* We run out of registers, tcp_len gets spilled to the stack, and the
	 * verifier forgets its min and max values checked above in tcp_dissect.
	 */
	hdr->tcp_len = hdr->tcp->doff * 4;
	if (hdr->tcp_len < sizeof(*hdr->tcp))
		return XDP_ABORTED;

	return hdr->tcp->syn ? syncookie_handle_syn(hdr, ctx, data, data_end, xdp) :
			       syncookie_handle_ack(hdr);
}

SEC("xdp")
int syncookie_xdp(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct header_pointers hdr;
	int ret;

	ret = syncookie_part1(ctx, data, data_end, &hdr, true);
	if (ret != XDP_TX)
		return ret;

	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;

	return syncookie_part2(ctx, data, data_end, &hdr, true);
}

struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(max_entries, 2);
        __uint(key_size, sizeof(__u32));
        __uint(value_size, sizeof(__u32));
        __array(values, int (void *));
} jmp_syncookie_table SEC(".maps") = {
        .values = {
                [SYN_COOKIE_VERIFY] = (void *)&syncookie_xdp,
        },
};

SEC("xdp")
int xdp_packet(struct xdp_md *ctx)
{
	struct meta_data *md = (void *)(long)ctx->data_meta;
	struct cursor     c;
	struct ethhdr    *eth;
	struct ipv6hdr   *ipv6;
	struct iphdr     *ipv4;
	struct udphdr    *udp;
	struct dnshdr    *dns;
	__u64         *count;

	if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct meta_data)))
		return XDP_PASS;

	cursor_init(&c, ctx);
	md = (void *)(long)ctx->data_meta;
	if ((void *)(md + 1) > c.pos)
		return XDP_PASS;

	if (!(eth = parse_eth(&c, &md->eth_proto)))
		return XDP_PASS;
	md->ip_pos = c.pos - (void *)eth;

	if (md->eth_proto == __bpf_htons(ETH_P_IPV6)) {
		if (!(ipv6 = parse_ipv6hdr(&c)))
			return XDP_PASS; /* Not IPV6 */
		switch (ipv6->nexthdr) {
		case IPPROTO_UDP:
			if (!(udp = parse_udphdr(&c))
			|| !(udp->dest == __bpf_htons(DNS_PORT))
			|| !(dns = parse_dnshdr(&c)))
				return XDP_PASS; /* Not DNS */
			// search for the prefix in the LPM trie
			struct {
				__u32        prefixlen;
				struct in6_addr ipv6_addr;
			} key6 = {
				.prefixlen = 64,
				.ipv6_addr = ipv6->daddr
			};
			// if the prefix matches, we exclude it from rate limiting
			if ((count=bpf_map_lookup_elem(&exclude_v6_prefixes, &key6))) {
				lock_xadd(count, 1);
				return XDP_PASS;
			}
			if (dns->flags.as_bits_and_pieces.qr
			||  dns->qdcount != __bpf_htons(1)
			||  dns->ancount || dns->nscount
			||  dns->arcount >  __bpf_htons(2)
			||  !skip_dname(&c)
			||  !parse_dns_qrr(&c))
				return XDP_ABORTED; // Return FORMERR?

			if (dns->arcount == 0) {
				bpf_tail_call(ctx, &jmp_rate_table, DO_RATE_LIMIT_IPV6);
				return XDP_PASS;
			}
			if (c.pos + 1 > c.end
			||  *(__u8 *)c.pos != 0)
				return XDP_ABORTED; // Return FORMERR?

			md->opt_pos = c.pos + 1 - (void *)(ipv6 + 1);
			bpf_tail_call(ctx, &jmp_cookie_table, COOKIE_VERIFY_IPv6);

			break;

		case IPPROTO_TCP:
			bpf_tail_call(ctx, &jmp_syncookie_table, SYN_COOKIE_VERIFY);
			break;
		}
	} else if (md->eth_proto == __bpf_htons(ETH_P_IP)) {
		if (!(ipv4 = parse_iphdr(&c)))
			return XDP_PASS; /* Not IPv4 */
		switch (ipv4->protocol) {
		case IPPROTO_UDP:
			if (!(udp = parse_udphdr(&c))
			|| !(udp->dest == __bpf_htons(DNS_PORT))
			|| !(dns = parse_dnshdr(&c)))
				return XDP_PASS; /* Not DNS */
			// search for the prefix in the LPM trie
			struct {
				__u32 prefixlen;
				__u32 ipv4_addr;
			} key4 = {
				.prefixlen = 32,
				.ipv4_addr = ipv4->saddr
			};

			// if the prefix matches, we exclude it from rate limiting
			if ((count=bpf_map_lookup_elem(&exclude_v4_prefixes, &key4))) {
				lock_xadd(count, 1);
				return XDP_PASS;
			}

			if (dns->flags.as_bits_and_pieces.qr
			||  dns->qdcount != __bpf_htons(1)
			||  dns->ancount || dns->nscount
			||  dns->arcount >  __bpf_htons(2)
			||  !skip_dname(&c)
			||  !parse_dns_qrr(&c))
				return XDP_ABORTED; // return FORMERR?

			if (dns->arcount == 0) {
				bpf_tail_call(ctx, &jmp_rate_table, DO_RATE_LIMIT_IPV4);
				return XDP_PASS;
			}
			if (c.pos + 1 > c.end
			||  *(__u8 *)c.pos != 0)
				return XDP_ABORTED; // Return FORMERR?

			md->opt_pos = c.pos + 1 - (void *)(ipv4 + 1);
			bpf_tail_call(ctx, &jmp_cookie_table, COOKIE_VERIFY_IPv4);

			break;

		case IPPROTO_TCP:
			bpf_tail_call(ctx, &jmp_syncookie_table, SYN_COOKIE_VERIFY);
			break;
		}

	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
