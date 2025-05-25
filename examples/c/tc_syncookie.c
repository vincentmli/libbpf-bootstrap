// SPDX-License-Identifier: GPL-2.0
/* BPF syncookie loader with guaranteed TC cleanup */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "tc_syncookie.skel.h"

static struct tc_syncookie_bpf *skel = NULL;
static char ifname[IF_NAMESIZE] = "lo";
static int ifindex = 0;
static __u32 attached_handle = 0;
static __u32 attached_priority = 0;

static void cleanup(int sig)
{
    printf("\nCleaning up TC rules on %s...\n", ifname);

    // Remove filter if we have the handle/priority
    if (attached_handle && attached_priority) {
        struct bpf_tc_hook hook = {};
        struct bpf_tc_opts opts = {};
        
        hook.sz = sizeof(hook);
        hook.ifindex = ifindex;
        hook.attach_point = BPF_TC_INGRESS;
        
        opts.sz = sizeof(opts);
        opts.handle = attached_handle;
        opts.priority = attached_priority;
        
        if (!bpf_tc_detach(&hook, &opts)) {
            printf("Removed BPF filter (handle: 0x%x, priority: %u)\n",
                   attached_handle, attached_priority);
        }
    }

    // Always attempt qdisc removal
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s clsact 2>/dev/null", ifname);
    int ret = system(cmd);
    if (ret == 0) {
        printf("Removed clsact qdisc from %s\n", ifname);
    } else {
        printf("No clsact qdisc found on %s\n", ifname);
    }

    // Destroy BPF program
    if (skel) {
        tc_syncookie_bpf__destroy(skel);
        printf("Destroyed BPF program\n");
    }
    
    exit(0);
}

static int attach_bpf_program(void)
{
    struct bpf_tc_hook hook = {};
    struct bpf_tc_opts opts = {};
    
    // Initialize hook
    hook.sz = sizeof(hook);
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_INGRESS;

    // Create qdisc
    int err = bpf_tc_hook_create(&hook);
    if (err) {
        fprintf(stderr, "Failed to create clsact qdisc on %s: %s\n", 
                ifname, strerror(-err));
        return -1;
    }

    // Set up attach options
    opts.sz = sizeof(opts);
    opts.prog_fd = bpf_program__fd(skel->progs.tcp_custom_syncookie);
    opts.flags = BPF_TC_F_REPLACE;

    // Attach program
    err = bpf_tc_attach(&hook, &opts);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program to %s: %s\n",
                ifname, strerror(-err));
        return -1;
    }

    // Save identification for cleanup
    attached_handle = opts.handle;
    attached_priority = opts.priority;
    
    printf("Successfully attached BPF program to %s (handle: 0x%x, priority: %u)\n",
           ifname, attached_handle, attached_priority);
    return 0;
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [-i interface]\n", prog);
    printf("Options:\n");
    printf("  -i <ifname>  Network interface to attach to (default: lo)\n");
}

int main(int argc, char **argv)
{
    int opt;
    
    // Parse command line
    while ((opt = getopt(argc, argv, "i:h")) != -1) {
        switch (opt) {
        case 'i':
            strncpy(ifname, optarg, IF_NAMESIZE - 1);
            ifname[IF_NAMESIZE - 1] = '\0';
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    // Get interface index
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Interface %s not found: %s\n", ifname, strerror(errno));
        return 1;
    }

    // Set up signal handlers
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    
    // Load BPF program
    skel = tc_syncookie_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF program\n");
        return 1;
    }

    // Attach to TC
    if (attach_bpf_program()) {
        cleanup(0);
        return 1;
    }

    printf("Running on %s... Press Ctrl+C to exit\n", ifname);
    while (1) {
        sleep(1);
        printf("Stats: SYN=%u ACK=%u\n", skel->bss->handled_syn, skel->bss->handled_ack);
    }

    return 0;
}
