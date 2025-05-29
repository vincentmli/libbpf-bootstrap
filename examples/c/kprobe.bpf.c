// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
        pid_t pid;
        const char *filename;

        pid = bpf_get_current_pid_tgid() >> 32;
        filename = BPF_CORE_READ(name, name);
        bpf_printk("KPROBE ENTRY pid = %d, filename = %s\n", pid, filename);
        return 0;
}

SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit, long ret)
{
        pid_t pid;

        pid = bpf_get_current_pid_tgid() >> 32;
        bpf_printk("KPROBE EXIT: pid = %d, ret = %ld\n", pid, ret);
        return 0;
}

SEC("kprobe/cookie_v4_check")
int BPF_KPROBE(cookie_v4_check, struct sock *sk, struct sk_buff *skb) {
  struct tcphdr tcph = {};
  int sk_state = 0;
  // Get socket state if socket exists
  if (sk) {
    sk_state = BPF_CORE_READ(sk, __sk_common.skc_state);
    bpf_printk("cookie_v4_check: state=%d", sk_state);
  }

  if (bpf_probe_read_kernel(&tcph, sizeof(tcph),
                            BPF_CORE_READ(skb, head) +
                                BPF_CORE_READ(skb, transport_header)) == 0) {
    u16 dest_port = bpf_htons(tcph.dest);
    u16 src_port = bpf_htons(tcph.source);
    bpf_printk("cookie_v4_check: src=%d dest=%d", src_port, dest_port);
    return 0;
  }
  return 0;
}

SEC("kprobe/tcp_v4_rcv")
int BPF_KPROBE(tcp_v4_rcv, struct sk_buff *skb) {
  struct tcphdr tcph = {};
  struct sock *sk = BPF_CORE_READ(skb, sk);
  int sk_state = 0;

  // Read TCP header (transport layer)
  if (bpf_probe_read_kernel(&tcph, sizeof(tcph),
                            BPF_CORE_READ(skb, head) +
                                BPF_CORE_READ(skb, transport_header)))
    return 0;

  // Extract key fields
  u16 src_port = bpf_htons(tcph.source);
  u16 dest_port = bpf_htons(tcph.dest);
  if (dest_port != 444)
    return 0;

  // Get socket state if socket exists
  if (sk) {
    sk_state = BPF_CORE_READ(sk, __sk_common.skc_state);
    bpf_printk("tcp_v4_rcv: state=%d", sk_state);
  }

  // Initialize flags string with '.' (unset flags)
  char flags_str[6] = "....."; // Default: all flags unset

  // Set active flags
  if (tcph.fin)
    flags_str[0] = 'F';
  if (tcph.syn)
    flags_str[1] = 'S';
  if (tcph.rst)
    flags_str[2] = 'R';
  if (tcph.psh)
    flags_str[3] = 'P'; // PUSH flag (data packet)
  if (tcph.ack)
    flags_str[4] = 'A';
  if (tcph.urg)
    flags_str[5] = 'U';

  // Get sequence number (network byte order -> host)
  u32 seq_num = bpf_ntohl(tcph.seq);

  bpf_printk("tcp_v4_rcv: src=%d dest=%d seq=%u flags=%s",
             bpf_htons(tcph.source), dest_port, seq_num, flags_str);

  return 0;
}
