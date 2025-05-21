#ifndef __NETQTOP_H
#define __NETQTOP_H

#define IFNAMSIZ 16
#define MAX_QUEUE_NUM 1024

union name_buf {
    char name[IFNAMSIZ];
    struct {
        __u64 hi;
        __u64 lo;
    } name_int;
};

struct queue_data {
    __u64 total_pkt_len;
    __u32 num_pkt;
    __u32 size_64B;
    __u32 size_512B;
    __u32 size_2K;
    __u32 size_16K;
    __u32 size_64K;
};

#endif /* __NETQTOP_H */
