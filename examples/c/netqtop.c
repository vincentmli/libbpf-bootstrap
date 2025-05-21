#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <stdint.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "netqtop.h"
#include "netqtop.skel.h"

#define ROOT_PATH "/sys/class/net"
#define COL_WIDTH 10

static struct env {
    const char *name;
    float interval;
    bool throughput;
} env;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static void to_str(uint64_t num, char *buf, size_t buf_len)
{
    if (num > 1000000) {
        snprintf(buf, buf_len, "%.2fM", num / (1024 * 1024.0));
    } else if (num > 1000) {
        snprintf(buf, buf_len, "%.2fK", num / 1024.0);
    } else {
        snprintf(buf, buf_len, "%llu", (unsigned long long)num);
    }
}

static void print_table(struct queue_data *entries, uint32_t *keys, int count, int qnum, bool is_tx)
{
    char buf[32];
    uint64_t tBPS = 0, tPPS = 0, tAVG = 0;
    uint64_t tGroup[5] = {0};
    uint64_t tpkt = 0, tlen = 0;
    
    // Calculate totals
    for (int i = 0; i < count; i++) {
        tlen += entries[i].total_pkt_len;
        tpkt += entries[i].num_pkt;
        tGroup[0] += entries[i].size_64B;
        tGroup[1] += entries[i].size_512B;
        tGroup[2] += entries[i].size_2K;
        tGroup[3] += entries[i].size_16K;
        tGroup[4] += entries[i].size_64K;
    }
    
    tBPS = tlen / env.interval;
    tPPS = tpkt / env.interval;
    tAVG = tpkt ? tlen / tpkt : 0;
    
    // Print headers
    printf("%s\n", is_tx ? "TX" : "RX");
    printf(" %-11s%-11s%-11s%-11s%-11s%-11s%-11s", 
           "QueueID", "avg_size", "[0, 64)", "[64, 512)", 
           "[512, 2K)", "[2K, 16K)", "[16K, 64K)");
    if (env.throughput)
        printf("%-11s%-11s", "BPS", "PPS");
    printf("\n");
    
    // Print each queue
    for (int k = 0; k < qnum; k++) {
        struct queue_data data = {0};
        
        for (int i = 0; i < count; i++) {
            if (keys[i] == k) {
                data = entries[i];
                break;
            }
        }
        
        uint64_t avg = data.num_pkt ? data.total_pkt_len / data.num_pkt : 0;
        printf(" %-11d", k);
        
        to_str(avg, buf, sizeof(buf));
        printf("%-11s", buf);
        
        to_str(data.size_64B, buf, sizeof(buf));
        printf("%-11s", buf);
        
        to_str(data.size_512B, buf, sizeof(buf));
        printf("%-11s", buf);
        
        to_str(data.size_2K, buf, sizeof(buf));
        printf("%-11s", buf);
        
        to_str(data.size_16K, buf, sizeof(buf));
        printf("%-11s", buf);
        
        to_str(data.size_64K, buf, sizeof(buf));
        printf("%-11s", buf);
        
        if (env.throughput) {
            uint64_t BPS = data.total_pkt_len / env.interval;
            uint64_t PPS = data.num_pkt / env.interval;
            
            to_str(BPS, buf, sizeof(buf));
            printf("%-11s", buf);
            
            to_str(PPS, buf, sizeof(buf));
            printf("%-11s", buf);
        }
        printf("\n");
    }
    
    // Print totals
    printf(" Total      ");
    to_str(tAVG, buf, sizeof(buf));
    printf("%-11s", buf);
    
    for (int i = 0; i < 5; i++) {
        to_str(tGroup[i], buf, sizeof(buf));
        printf("%-11s", buf);
    }
    
    if (env.throughput) {
        to_str(tBPS, buf, sizeof(buf));
        printf("%-11s", buf);
        
        to_str(tPPS, buf, sizeof(buf));
        printf("%-11s", buf);
    }
    printf("\n");
}

static int get_queue_count(const char *dev_name, bool is_tx)
{
    char path[256];
    int count = 0;
    DIR *dir;
    struct dirent *entry;
    
    snprintf(path, sizeof(path), "%s/%s/queues", ROOT_PATH, dev_name);
    dir = opendir(path);
    if (!dir)
        return -1;
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR && entry->d_name[0] == (is_tx ? 't' : 'r'))
            count++;
    }
    
    closedir(dir);
    return count;
}

int main(int argc, char **argv)
{
    struct netqtop_bpf *skel;
    int err;
    time_t t;
    
    // Parse arguments
    if (argc < 2) {
        fprintf(stderr, "Usage: %s --name <interface> [--interval <seconds>] [--throughput]\n", argv[0]);
        return 1;
    }
    
    env.name = "";
    env.interval = 1.0;
    env.throughput = false;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--name") == 0 || strcmp(argv[i], "-n") == 0) {
            if (i + 1 < argc) {
                env.name = argv[++i];
            } else {
                fprintf(stderr, "Please specify a network interface.\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--interval") == 0 || strcmp(argv[i], "-i") == 0) {
            if (i + 1 < argc) {
                env.interval = atof(argv[++i]);
            } else {
                fprintf(stderr, "Please specify an interval.\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--throughput") == 0 || strcmp(argv[i], "-t") == 0) {
            env.throughput = true;
        }
    }
    
    if (strlen(env.name) == 0) {
        fprintf(stderr, "Please specify a network interface.\n");
        return 1;
    }
    
    if (strlen(env.name) >= IFNAMSIZ) {
        fprintf(stderr, "NIC name too long\n");
        return 1;
    }
    
    if (env.interval <= 0) {
        fprintf(stderr, "Print interval must be positive\n");
        return 1;
    }
    
    // Get queue counts
    int tx_num = get_queue_count(env.name, true);
    int rx_num = get_queue_count(env.name, false);
    
    if (tx_num < 0 || rx_num < 0) {
        fprintf(stderr, "Net interface %s does not exist or has no queues\n", env.name);
        return 1;
    }
    
    if (tx_num > MAX_QUEUE_NUM || rx_num > MAX_QUEUE_NUM) {
        fprintf(stderr, "Number of queues over %d is not supported\n", MAX_QUEUE_NUM);
        return 1;
    }
    
    // Set up libbpf
    libbpf_set_print(libbpf_print_fn);
    
    // Load and verify BPF application
    skel = netqtop_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    
    // Load and verify BPF programs
    err = netqtop_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }
    
    // Set device name
    union name_buf name = {};
    strncpy(name.name, env.name, IFNAMSIZ - 1);
    name.name[IFNAMSIZ - 1] = '\0'; // Ensure null termination

    int map_fd = bpf_map__fd(skel->maps.name_map);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get name_map fd: %d\n", map_fd);
        err = map_fd;
        goto cleanup;
    }

    uint32_t key = 0;
    err = bpf_map_update_elem(map_fd, &key, &name, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to set device name: %s\n", strerror(-err));
        goto cleanup;
    }
    
    // Attach tracepoints
    err = netqtop_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }
    
    printf("Monitoring %s, TX queues: %d, RX queues: %d\n", 
           env.name, tx_num, rx_num);
    
    // Main loop
    // Update the map reading section in the main loop
while (1) {
    sleep(env.interval);
    time(&t);
    printf("%s", ctime(&t));

    // Process TX queues
    uint32_t tx_keys[MAX_QUEUE_NUM];
    struct queue_data tx_values[MAX_QUEUE_NUM];
    uint32_t tx_count = MAX_QUEUE_NUM;
    void *in_batch = NULL, *out_batch = NULL;

    map_fd = bpf_map__fd(skel->maps.tx_q);
    err = bpf_map_lookup_and_delete_batch(map_fd, &in_batch, &out_batch,
                                        tx_keys, tx_values, &tx_count, NULL);
    if (err < 0 && errno != ENOENT) {
        fprintf(stderr, "Failed to read TX map: %s (errno=%d)\n", strerror(errno), errno);
        // Fall back to non-batch operation if batch fails
        tx_count = 0;
        for (uint32_t i = 0; i < MAX_QUEUE_NUM; i++) {
            uint16_t key = i;
            if (bpf_map_lookup_and_delete_elem(map_fd, &key, &tx_values[tx_count]) == 0) {
                tx_keys[tx_count] = key;
                tx_count++;
            }
        }
    }

    print_table(tx_values, tx_keys, tx_count, tx_num, true);

    // Process RX queues
    uint32_t rx_keys[MAX_QUEUE_NUM];
    struct queue_data rx_values[MAX_QUEUE_NUM];
    uint32_t rx_count = MAX_QUEUE_NUM;
    in_batch = out_batch = NULL;

    map_fd = bpf_map__fd(skel->maps.rx_q);
    err = bpf_map_lookup_and_delete_batch(map_fd, &in_batch, &out_batch,
                                        rx_keys, rx_values, &rx_count, NULL);
    if (err < 0 && errno != ENOENT) {
        fprintf(stderr, "Failed to read RX map: %s (errno=%d)\n", strerror(errno), errno);
        // Fall back to non-batch operation if batch fails
        rx_count = 0;
        for (uint32_t i = 0; i < MAX_QUEUE_NUM; i++) {
            uint16_t key = i;
            if (bpf_map_lookup_and_delete_elem(map_fd, &key, &rx_values[rx_count]) == 0) {
                rx_keys[rx_count] = key;
                rx_count++;
            }
        }
    }

    print_table(rx_values, rx_keys, rx_count, rx_num, false);

    printf(env.throughput ? "----------------------------------------------\n"
                         : "----------------------------------\n");
    }

cleanup:
    netqtop_bpf__destroy(skel);
    return err;
}
