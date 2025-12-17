// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * tcpstates    Trace TCP session state changes with durations.
 * Copyright (c) 2021 Hengqi Chen
 *
 * Based on tcpstates(8) from BCC by Brendan Gregg.
 * 18-Dec-2021   Hengqi Chen   Created this.
 */
#include <getopt.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <stdlib.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "btf_helpers.h"
#include "tcpstates.h"
#include "tcpstates.skel.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES	16
#define PERF_POLL_TIMEOUT_MS	100
#define warn(...) fprintf(stderr, __VA_ARGS__)

static volatile sig_atomic_t exiting = 0;

static bool emit_timestamp = false;
static short target_family = 0;
static char *target_sports = NULL;
static char *target_dports = NULL;
static bool wide_output = false;
static bool verbose = false;
static const char *tcp_states[] = {
	[1] = "ESTABLISHED",
	[2] = "SYN_SENT",
	[3] = "SYN_RECV",
	[4] = "FIN_WAIT1",
	[5] = "FIN_WAIT2",
	[6] = "TIME_WAIT",
	[7] = "CLOSE",
	[8] = "CLOSE_WAIT",
	[9] = "LAST_ACK",
	[10] = "LISTEN",
	[11] = "CLOSING",
	[12] = "NEW_SYN_RECV",
	[13] = "UNKNOWN",
};

static void usage(const char *prog_name, int exit_code)
{
	fprintf(exit_code ? stderr : stdout,
		"Usage: %s [OPTION]...\n"
		"Trace TCP session state changes and durations.\n"
		"\n"
		"Examples:\n"
		"  %s                  # trace all TCP state changes\n"
		"  %s -T               # include timestamps\n"
		"  %s -L 80            # only trace local port 80\n"
		"  %s -D 80            # only trace remote port 80\n"
		"\n"
		"Options:\n"
		"  -h, --help          Show this help message and exit\n"
		"  -v, --verbose       Verbose debug output\n"
		"  -T, --timestamp     Include timestamp on output\n"
		"  -4, --ipv4          Trace IPv4 family only\n"
		"  -6, --ipv6          Trace IPv6 family only\n"
		"  -w, --wide          Wide column output (fits IPv6 addresses)\n"
		"  -L, --localport LPORT  Comma-separated list of local ports to trace\n"
		"  -D, --remoteport DPORT Comma-separated list of remote ports to trace\n",
		prog_name, prog_name, prog_name, prog_name, prog_name);
	exit(exit_code);
}

static int parse_port_list(const char *arg, char **save_ptr)
{
	char *input_copy;
	char *port_str;
	long port_num;
	char *endptr;

	if (!arg) {
		warn("No ports specified\n");
		return -1;
	}

	input_copy = strdup(arg);
	if (!input_copy) {
		warn("Memory allocation failed\n");
		return -1;
	}

	port_str = strtok(input_copy, ",");
	while (port_str) {
		errno = 0;
		port_num = strtol(port_str, &endptr, 10);
		
		if (errno != 0 || endptr == port_str || *endptr != '\0') {
			warn("Invalid port number: '%s'\n", port_str);
			free(input_copy);
			return -1;
		}
		
		if (port_num <= 0 || port_num > 65535) {
			warn("Port out of range (1-65535): %ld\n", port_num);
			free(input_copy);
			return -1;
		}
		
		port_str = strtok(NULL, ",");
	}
	
	free(input_copy);
	
	*save_ptr = strdup(arg);
	if (!*save_ptr) {
		warn("Memory allocation failed\n");
		return -1;
	}
	
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	char ts[32], saddr[39], daddr[39];
	struct event e;
	struct tm *tm;
	int family;
	time_t t;

	if (data_sz < sizeof(e)) {
		printf("Error: packet too small\n");
		return;
	}
	memcpy(&e, data, sizeof(e));

	if (emit_timestamp) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		printf("%8s ", ts);
	}

	inet_ntop(e.family, &e.saddr, saddr, sizeof(saddr));
	inet_ntop(e.family, &e.daddr, daddr, sizeof(daddr));
	if (wide_output) {
		family = e.family == AF_INET ? 4 : 6;
		printf("%-16llx %-7d %-16s %-2d %-39s %-5d %-39s %-5d %-11s -> %-11s %.3f\n",
		       e.skaddr, e.pid, e.task, family, saddr, e.sport, daddr, e.dport,
		       tcp_states[e.oldstate], tcp_states[e.newstate], (double)e.delta_us / 1000);
	} else {
		printf("%-16llx %-7d %-10.10s %-15s %-5d %-15s %-5d %-11s -> %-11s %.3f\n",
		       e.skaddr, e.pid, e.task, saddr, e.sport, daddr, e.dport,
		       tcp_states[e.oldstate], tcp_states[e.newstate], (double)e.delta_us / 1000);
	}
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	warn("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	static struct option long_options[] = {
		{"help",      no_argument,       0, 'h'},
		{"verbose",   no_argument,       0, 'v'},
		{"timestamp", no_argument,       0, 'T'},
		{"ipv4",      no_argument,       0, '4'},
		{"ipv6",      no_argument,       0, '6'},
		{"wide",      no_argument,       0, 'w'},
		{"localport", required_argument, 0, 'L'},
		{"remoteport",required_argument, 0, 'D'},
		{0, 0, 0, 0}
	};
	
	int opt;
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	struct perf_buffer *pb = NULL;
	struct tcpstates_bpf *obj;
	int err, port_map_fd;
	short port_num;
	char *port;

	while ((opt = getopt_long(argc, argv, "hvT46wL:D:", long_options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			usage(argv[0], 0);
			break;
		case 'v':
			verbose = true;
			break;
		case 'T':
			emit_timestamp = true;
			break;
		case '4':
			target_family = AF_INET;
			break;
		case '6':
			target_family = AF_INET6;
			break;
		case 'w':
			wide_output = true;
			break;
		case 'L':
			if (parse_port_list(optarg, &target_sports) < 0) {
				usage(argv[0], 1);
			}
			break;
		case 'D':
			if (parse_port_list(optarg, &target_dports) < 0) {
				usage(argv[0], 1);
			}
			break;
		case '?':
			usage(argv[0], 1);
			break;
		default:
			warn("Unexpected option: %c\n", opt);
			usage(argv[0], 1);
		}
	}
	
	if (optind < argc) {
		warn("Unexpected argument: %s\n", argv[optind]);
		usage(argv[0], 1);
	}

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		warn("failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = tcpstates_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->filter_by_sport = target_sports != NULL;
	obj->rodata->filter_by_dport = target_dports != NULL;
	obj->rodata->target_family = target_family;

	err = tcpstates_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	if (target_sports) {
		port_map_fd = bpf_map__fd(obj->maps.sports);
		port = strtok(target_sports, ",");
		while (port) {
			port_num = strtol(port, NULL, 10);
			bpf_map_update_elem(port_map_fd, &port_num, &port_num, BPF_ANY);
			port = strtok(NULL, ",");
		}
	}
	if (target_dports) {
		port_map_fd = bpf_map__fd(obj->maps.dports);
		port = strtok(target_dports, ",");
		while (port) {
			port_num = strtol(port, NULL, 10);
			bpf_map_update_elem(port_map_fd, &port_num, &port_num, BPF_ANY);
			port = strtok(NULL, ",");
		}
	}

	err = tcpstates_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES,
			      handle_event, handle_lost_events, NULL, NULL);
	if (!pb) {
		err = - errno;
		warn("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	if (emit_timestamp)
		printf("%-8s ", "TIME(s)");
	if (wide_output)
		printf("%-16s %-7s %-16s %-2s %-39s %-5s %-39s %-5s %-11s -> %-11s %s\n",
		       "SKADDR", "PID", "COMM", "IP", "LADDR", "LPORT",
		       "RADDR", "RPORT", "OLDSTATE", "NEWSTATE", "MS");
	else
		printf("%-16s %-7s %-10s %-15s %-5s %-15s %-5s %-11s -> %-11s %s\n",
		       "SKADDR", "PID", "COMM", "LADDR", "LPORT",
		       "RADDR", "RPORT", "OLDSTATE", "NEWSTATE", "MS");

	while (!exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			warn("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	tcpstates_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
	
	if (target_sports)
		free(target_sports);
	if (target_dports)
		free(target_dports);

	return err != 0;
}
