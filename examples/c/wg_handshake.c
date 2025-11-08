#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>

#include "wg_handshake.h"
#include "wg_handshake.skel.h"

static volatile bool exiting = false;
static struct wg_handshake_bpf *skel = NULL;
static struct ring_buffer *rb = NULL;

static void sig_handler(int sig)
{
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    char addr_str[INET6_ADDRSTRLEN];
    char log_msg[256];

    // Validate event size
    if (data_sz < sizeof(*e)) {
        return 0;
    }

    if (e->family == 2) { // AF_INET
        struct in_addr addr = { .s_addr = e->v4.addr };
        inet_ntop(AF_INET, &addr, addr_str, sizeof(addr_str));
        // Simplified logging - no interface
        snprintf(log_msg, sizeof(log_msg),
                "WireGuard handshake from peer %lu (%s:%d)",
                e->peer_id, addr_str, ntohs(e->v4.port));
    } else if (e->family == 10) { // AF_INET6
        inet_ntop(AF_INET6, &e->v6.addr, addr_str, sizeof(addr_str));
        snprintf(log_msg, sizeof(log_msg),
                "WireGuard handshake from peer %lu ([%s]:%d)",
                e->peer_id, addr_str, ntohs(e->v6.port));
    } else {
        snprintf(log_msg, sizeof(log_msg),
                "WireGuard handshake from peer %lu (unknown address family %d)",
                e->peer_id, e->family);
    }

    syslog(LOG_INFO, "%s", log_msg);
    printf("%s\n", log_msg);
    
    return 0;
}

int main(int argc, char **argv)
{
    int err;

    // Set up signal handlers for clean shutdown
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Set up libbpf errors and debug info callback
    libbpf_set_print(libbpf_print_fn);

    // Bump RLIMIT_MEMLOCK to allow BPF syscalls
    struct rlimit rlim = {
        .rlim_cur = 512UL << 20,
        .rlim_max = 512UL << 20,
    };
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    // Open and load BPF application
    skel = wg_handshake_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Load and verify BPF programs
    err = wg_handshake_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // Attach tracepoint
    err = wg_handshake_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.wg_events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    // Open syslog
    openlog("wireguard-handshake", LOG_PID | LOG_CONS, LOG_USER);
    syslog(LOG_INFO, "WireGuard handshake monitor started (with 60-second deduplication)");

    printf("Monitoring WireGuard handshakes (deduplicated every 60 seconds)...\n");
    printf("Press Ctrl-C to stop\n");
    
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        // Ctrl-C will break with -EINTR
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    syslog(LOG_INFO, "WireGuard handshake monitor stopped");
    closelog();
    
    if (rb) {
        ring_buffer__free(rb);
    }
    if (skel) {
        wg_handshake_bpf__destroy(skel);
    }
    
    return err < 0 ? -err : 0;
}
