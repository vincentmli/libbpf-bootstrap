#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "wg_handshake.h"

// Define endpoint structure based on WireGuard source
struct endpoint {
    union {
        struct sockaddr_in addr4;
        struct sockaddr_in6 addr6;
        struct sockaddr addr;
    };
    union {
        struct in_addr src4;
        struct in6_addr src6;
    };
    int src_if4;
};

struct wg_peer {
    unsigned long internal_id;
    struct endpoint endpoint;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} wg_events SEC(".maps");

// Deduplication map - track recent handshakes using (peer_id, ip, port) as key
struct handshake_key {
    unsigned long peer_id;
    __u32 ip;
    __u16 port;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct handshake_key);
    __type(value, __u64); // timestamp
} recent_handshakes SEC(".maps");

static __always_inline void read_ipv4_endpoint(struct event *e, const struct endpoint *endpoint)
{
    // Read IPv4 endpoint data using direct memory access
    bpf_probe_read_kernel(&e->v4.addr, sizeof(e->v4.addr), 
                         (void *)&endpoint->addr4.sin_addr.s_addr);
    bpf_probe_read_kernel(&e->v4.port, sizeof(e->v4.port), 
                         (void *)&endpoint->addr4.sin_port);
    // Removed interface reading
}

static __always_inline void read_ipv6_endpoint(struct event *e, const struct endpoint *endpoint)
{
    // Read IPv6 endpoint data using direct memory access
    bpf_probe_read_kernel(&e->v6.addr, sizeof(e->v6.addr), 
                         (void *)&endpoint->addr6.sin6_addr);
    bpf_probe_read_kernel(&e->v6.port, sizeof(e->v6.port), 
                         (void *)&endpoint->addr6.sin6_port);
    // Removed interface setting
}

static __always_inline int should_log_handshake(struct wg_peer *peer, const struct endpoint *endpoint)
{
    __u64 timestamp = bpf_ktime_get_ns();
    struct handshake_key key = {0};
    
    // Get peer internal ID
    key.peer_id = BPF_CORE_READ(peer, internal_id);
    
    // Create deduplication key based on endpoint
    __u16 family;
    bpf_probe_read_kernel(&family, sizeof(family), (void *)&endpoint->addr.sa_family);
    
    if (family == 2) { // AF_INET
        bpf_probe_read_kernel(&key.ip, sizeof(key.ip), 
                            (void *)&endpoint->addr4.sin_addr.s_addr);
        bpf_probe_read_kernel(&key.port, sizeof(key.port), 
                            (void *)&endpoint->addr4.sin_port);
    } else if (family == 10) { // AF_INET6
        // For IPv6, use first 4 bytes as key (simplified deduplication)
        bpf_probe_read_kernel(&key.ip, sizeof(key.ip), 
                            (void *)&endpoint->addr6.sin6_addr);
        bpf_probe_read_kernel(&key.port, sizeof(key.port), 
                            (void *)&endpoint->addr6.sin6_port);
    }
    
    // Check if we've seen this handshake recently (within 120 seconds)
    __u64 *last_seen = bpf_map_lookup_elem(&recent_handshakes, &key);
    if (last_seen) {
        // If seen within 120 seconds, skip logging
        if (timestamp - *last_seen < 120 * 1000000000ULL) {
            return 0;
        }
    }
    
    // Update timestamp and allow logging
    bpf_map_update_elem(&recent_handshakes, &key, &timestamp, BPF_ANY);
    return 1;
}

SEC("fentry/wg_socket_set_peer_endpoint")
int BPF_PROG(wg_socket_set_peer_endpoint_hook, struct wg_peer *peer, const struct endpoint *endpoint)
{
    struct event *e;
    
    // Check if we should log this handshake (deduplication)
    if (!should_log_handshake(peer, endpoint)) {
        return 0;
    }
    
    e = bpf_ringbuf_reserve(&wg_events, sizeof(*e), 0);
    if (!e)
        return 0;

    // Initialize event with defaults
    __builtin_memset(e, 0, sizeof(*e));

    // Get peer internal ID
    e->peer_id = BPF_CORE_READ(peer, internal_id);
    
    // Safely read the address family
    bpf_probe_read_kernel(&e->family, sizeof(e->family), (void *)&endpoint->addr.sa_family);
    
    // Use numeric constants for address families
    if (e->family == 2) { // AF_INET = 2
        read_ipv4_endpoint(e, endpoint);
    } else if (e->family == 10) { // AF_INET6 = 10
        read_ipv6_endpoint(e, endpoint);
    }
    // For unknown address families, the event will have zeroed data

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
