#ifndef __WG_HANDSHAKE_H
#define __WG_HANDSHAKE_H

struct event {
    unsigned long peer_id;
    __u16 family;
    union {
        struct {
            __be32 addr;
            __be16 port;
        } v4;
        struct {
            struct in6_addr addr;
            __be16 port;
        } v6;
    };
};

#endif /* __WG_HANDSHAKE_H */
