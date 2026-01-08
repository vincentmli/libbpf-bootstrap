// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright LoongFire */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_tracing_net.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TASK_COMM_LEN 16

struct app_name {
    char str[TASK_COMM_LEN];
};

// Map 1: Work mode (0 = all apps, 1 = target mode)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, int);
} work_mode SEC(".maps");

// Map 2: Target applications (by name)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct app_name);
    __type(value, int);
} target_apps SEC(".maps");

// Map 3: Target PIDs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} target_pids SEC(".maps");

SEC("fmod_ret/update_socket_protocol")
int BPF_PROG(mptcpify, int family, int type, int protocol)
{
    struct app_name app = {};
    __u32 pid;
    int index = 0;
    int *mode;
    int *found;
    __u32 *pid_found;
    
    // Get current process info
    pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&app.str, sizeof(app.str));
    
    // Check work mode
    mode = bpf_map_lookup_elem(&work_mode, &index);
    if (!mode)
        return protocol;
    
    // Only handle TCP sockets
    if (!((family == AF_INET || family == AF_INET6) &&
          type == SOCK_STREAM &&
          (!protocol || protocol == IPPROTO_TCP))) {
        return protocol;
    }
    
    // Mode 0: Force MPTCP for all applications
    if (*mode == 0) {
        return IPPROTO_MPTCP;
    }
    
    // Mode 1: Check specific targets
    // First check by PID
    pid_found = bpf_map_lookup_elem(&target_pids, &pid);
    if (pid_found) {
        return IPPROTO_MPTCP;
    }
    
    // Then check by app name
    found = bpf_map_lookup_elem(&target_apps, &app);
    if (found) {
        return IPPROTO_MPTCP;
    }
    
    return protocol;
}
