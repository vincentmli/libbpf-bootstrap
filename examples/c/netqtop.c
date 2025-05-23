#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <stdint.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "netqtop.h"
#include "netqtop.skel.h"

#define ROOT_PATH     "/sys/class/net"
#define COL_WIDTH     10
#define BITS_PER_BYTE 8

static struct env {
	const char *name;
	float interval;
	bool throughput;
	bool show_protocols;
} env;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void to_str(uint64_t num, char *buf, size_t buf_len, bool is_bits)
{
	if (is_bits) {
		num *= BITS_PER_BYTE; // Convert bytes to bits
		if (num > 1000000000) {
			snprintf(buf, buf_len, "%.2fG", num / 1000000000.0);
		} else if (num > 1000000) {
			snprintf(buf, buf_len, "%.2fM", num / 1000000.0);
		} else if (num > 1000) {
			snprintf(buf, buf_len, "%.2fK", num / 1000.0);
		} else {
			snprintf(buf, buf_len, "%llu", (unsigned long long)num);
		}
	} else {
		if (num > 1000000) {
			snprintf(buf, buf_len, "%.2fM", num / (1024 * 1024.0));
		} else if (num > 1000) {
			snprintf(buf, buf_len, "%.2fK", num / 1024.0);
		} else {
			snprintf(buf, buf_len, "%llu", (unsigned long long)num);
		}
	}
}

static void print_table(struct queue_data *entries, uint32_t *keys, int count, int qnum, bool is_tx)
{
	char buf[32];
	uint64_t tbps = 0, tPPS = 0, tAVG = 0, tSYN = 0;
	uint64_t tGroup[5] = { 0 };
	uint64_t tpkt = 0, tlen = 0;
	uint64_t tcp = 0, udp = 0, icmp = 0, other = 0;

	for (int i = 0; i < count; i++) {
		tlen += entries[i].total_pkt_len;
		tpkt += entries[i].num_pkt;
		tSYN += entries[i].syn_packets;
		tGroup[0] += entries[i].size_64B;
		tGroup[1] += entries[i].size_512B;
		tGroup[2] += entries[i].size_2K;
		tGroup[3] += entries[i].size_16K;
		tGroup[4] += entries[i].size_64K;
		tcp += entries[i].tcp_pkts;
		udp += entries[i].udp_pkts;
		icmp += entries[i].icmp_pkts;
		other += entries[i].other_pkts;
	}

	tbps = (tlen * BITS_PER_BYTE) / env.interval; // Convert to bits per second
	tPPS = tpkt / env.interval;
	tAVG = tpkt ? tlen / tpkt : 0;

	printf("%s\n", is_tx ? "TX" : "RX");
	printf(" %-11s%-11s%-11s%-11s%-11s%-11s%-11s%-11s", "QueueID", "avg_size", "[0, 64)",
	       "[64, 512)", "[512, 2K)", "[2K, 16K)", "[16K, 64K)", "SYN");

	if (env.show_protocols)
		printf("%-11s%-11s%-11s%-11s", "TCP", "UDP", "ICMP", "Other");

	if (env.throughput)
		printf("%-11s%-11s", "bps", "PPS");

	printf("\n");

	for (int k = 0; k < qnum; k++) {
		struct queue_data data = { 0 };

		for (int i = 0; i < count; i++) {
			if (keys[i] == k) {
				data = entries[i];
				break;
			}
		}

		uint64_t avg = data.num_pkt ? data.total_pkt_len / data.num_pkt : 0;
		printf(" %-11d", k);

		to_str(avg, buf, sizeof(buf), false);
		printf("%-11s", buf);

		to_str(data.size_64B, buf, sizeof(buf), false);
		printf("%-11s", buf);

		to_str(data.size_512B, buf, sizeof(buf), false);
		printf("%-11s", buf);

		to_str(data.size_2K, buf, sizeof(buf), false);
		printf("%-11s", buf);

		to_str(data.size_16K, buf, sizeof(buf), false);
		printf("%-11s", buf);

		to_str(data.size_64K, buf, sizeof(buf), false);
		printf("%-11s", buf);

		to_str(data.syn_packets, buf, sizeof(buf), false);
		printf("%-11s", buf);

		if (env.show_protocols) {
			to_str(data.tcp_pkts, buf, sizeof(buf), false);
			printf("%-11s", buf);

			to_str(data.udp_pkts, buf, sizeof(buf), false);
			printf("%-11s", buf);

			to_str(data.icmp_pkts, buf, sizeof(buf), false);
			printf("%-11s", buf);

			to_str(data.other_pkts, buf, sizeof(buf), false);
			printf("%-11s", buf);
		}

		if (env.throughput) {
			uint64_t bps = (data.total_pkt_len * BITS_PER_BYTE) / env.interval;
			to_str(bps, buf, sizeof(buf), true);
			printf("%-11s", buf);

			to_str(tPPS, buf, sizeof(buf), false);
			printf("%-11s", buf);
		}
		printf("\n");
	}

	printf(" Total      ");
	to_str(tAVG, buf, sizeof(buf), false);
	printf("%-11s", buf);

	for (int i = 0; i < 5; i++) {
		to_str(tGroup[i], buf, sizeof(buf), false);
		printf("%-11s", buf);
	}

	to_str(tSYN, buf, sizeof(buf), false);
	printf("%-11s", buf);

	if (env.show_protocols) {
		to_str(tcp, buf, sizeof(buf), false);
		printf("%-11s", buf);

		to_str(udp, buf, sizeof(buf), false);
		printf("%-11s", buf);

		to_str(icmp, buf, sizeof(buf), false);
		printf("%-11s", buf);

		to_str(other, buf, sizeof(buf), false);
		printf("%-11s", buf);
	}

	if (env.throughput) {
		to_str(tbps, buf, sizeof(buf), true);
		printf("%-11s", buf);

		to_str(tPPS, buf, sizeof(buf), false);
		printf("%-11s", buf);
	}
	printf("\n");

	// SYN flood warning
	if (tSYN > 0 && (double)tSYN / (double)tpkt > 0.1) {
		printf("\n\033[1;31mWARNING: Potential SYN flood detected! (%.1f%% of packets are SYN-only)\033[0m\n",
		       (double)tSYN * 100.0 / (double)tpkt);
	}
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

	// Set default values
	env.name = "";
	env.interval = 1.0;
	env.throughput = false;
	env.show_protocols = false;

	// Parse arguments
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
			}
		} else if (strcmp(argv[i], "--throughput") == 0 || strcmp(argv[i], "-t") == 0) {
			env.throughput = true;
		} else if (strcmp(argv[i], "--protocols") == 0 || strcmp(argv[i], "-p") == 0) {
			env.show_protocols = true;
		}
	}

	if (strlen(env.name) == 0) {
		fprintf(stderr, "Please specify a network interface with --name\n");
		return 1;
	}

	if (strlen(env.name) >= IFNAMSIZ) {
		fprintf(stderr, "Interface name too long (max %d chars)\n", IFNAMSIZ - 1);
		return 1;
	}

	int tx_num = get_queue_count(env.name, true);
	int rx_num = get_queue_count(env.name, false);

	if (tx_num < 0 || rx_num < 0) {
		fprintf(stderr, "Cannot get queue counts for %s\n", env.name);
		return 1;
	}

	libbpf_set_print(libbpf_print_fn);

	skel = netqtop_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	err = netqtop_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF program\n");
		goto cleanup;
	}

	// Set interface name
	union name_buf name = {};
	strncpy(name.name, env.name, IFNAMSIZ - 1);
	int map_fd = bpf_map__fd(skel->maps.name_map);
	__u32 key = 0;
	err = bpf_map_update_elem(map_fd, &key, &name, BPF_ANY);
	if (err) {
		fprintf(stderr, "Failed to set device name\n");
		goto cleanup;
	}

	err = netqtop_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF program\n");
		goto cleanup;
	}

	printf("Monitoring %s - TXQs: %d, RXQs: %d\n", env.name, tx_num, rx_num);
	printf("Protocol stats: %s | Throughput: %s\n", env.show_protocols ? "ON" : "OFF",
	       env.throughput ? "ON" : "OFF");

	while (1) {
		sleep(env.interval);
		time(&t);
		printf("\n%s", ctime(&t));

		// Process TX queues
		uint32_t tx_keys[MAX_QUEUE_NUM];
		struct queue_data tx_values[MAX_QUEUE_NUM];
		uint32_t tx_count = 0;

		map_fd = bpf_map__fd(skel->maps.tx_q);
		for (uint32_t i = 0; i < MAX_QUEUE_NUM; i++) {
			uint16_t key = i;
			if (bpf_map_lookup_and_delete_elem(map_fd, &key, &tx_values[tx_count]) ==
			    0) {
				tx_keys[tx_count] = key;
				tx_count++;
			}
		}
		print_table(tx_values, tx_keys, tx_count, tx_num, true);

		// Process RX queues
		uint32_t rx_keys[MAX_QUEUE_NUM];
		struct queue_data rx_values[MAX_QUEUE_NUM];
		uint32_t rx_count = 0;

		map_fd = bpf_map__fd(skel->maps.rx_q);
		for (uint32_t i = 0; i < MAX_QUEUE_NUM; i++) {
			uint16_t key = i;
			if (bpf_map_lookup_and_delete_elem(map_fd, &key, &rx_values[rx_count]) ==
			    0) {
				rx_keys[rx_count] = key;
				rx_count++;
			}
		}
		print_table(rx_values, rx_keys, rx_count, rx_num, false);
	}

cleanup:
	netqtop_bpf__destroy(skel);
	return err;
}
