#include <net/if.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "dnsrrl.skel.h"

#define IFINDEX_LO 1
#define XDP_FLAGS_REPLACE		(1U << 4)

#ifndef DEFAULT_IFACE
#define DEFAULT_IFACE "lo"
#endif
#define DEFAULT_IPv4_VIP_PINPATH "/sys/fs/bpf/rrl_exclude_v4_prefixes"
#define DEFAULT_IPv6_VIP_PINPATH "/sys/fs/bpf/rrl_exclude_v6_prefixes"
#define DEFAULT_RATELIMIT 10
#define DEFAULT_CPUS 1

#define EXCLv4_TBL "exclude_v4_prefixes"
#define EXCLv6_TBL "exclude_v6_prefixes"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

void print_usage(FILE *out, const char *program_name)
{
	fprintf( out
	       , "Usage: %s [-i interface]\n"
				" [-4 IPv4 V.I.P. pinpath]\n"
	                        " [-6 IPv6 V.I.P. pinpath]\n"
	                        " [-r number of DNS Response Ratelimit]\n"
	                        " [-c number of CPUs]\n"
	         "Default values:\n"
	         "  - interface: " DEFAULT_IFACE "\n"
	         "  - IPv4 V.I.P. pinpath: \"" DEFAULT_IPv4_VIP_PINPATH "\"\n"
	         "  - IPv6 V.I.P. pinpath: \"" DEFAULT_IPv6_VIP_PINPATH "\"\n"
	       , program_name);
}

int main(int argc, char **argv)
{
	const char *ifname = DEFAULT_IFACE;
	const char *exclude_v4_pinpath = DEFAULT_IPv4_VIP_PINPATH;
	const char *exclude_v6_pinpath = DEFAULT_IPv6_VIP_PINPATH;
	int fd, opt = -1;
	unsigned int ifindex = 0;
	unsigned int ratelimit = DEFAULT_RATELIMIT;
	unsigned int cpus = DEFAULT_CPUS;

	LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
	struct dnsrrl_bpf *skel;

	while ((opt = getopt(argc, argv, "hi:4:6:r:c:")) != -1) {
		switch(opt) {
		case 'i':
			ifname = optarg;
			break;
		case '4':
			exclude_v4_pinpath = optarg;
			break;
		case '6':
			exclude_v4_pinpath = optarg;
			break;
		case 'r':
			ratelimit = optarg;
			break;
		case 'c':
			cpus = optarg;
			break;
		case 'h':
			print_usage(stdout, argv[0]);
			exit(EXIT_SUCCESS);
		default:
			fprintf(stderr, "OPT: %d ('%c')\n", opt, (char)opt);
			print_usage(stderr, argv[0]);
			exit(EXIT_FAILURE);
		}
	}
	if (!(ifindex = if_nametoindex(ifname)))
		fprintf(stderr, "ERROR: error finding device %s: %s\n"
		              , ifname, strerror(errno));

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF programs*/
	skel = dnsrrl_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	fd = bpf_program__fd(skel->progs.xdp_dns_cookies);

	if (bpf_xdp_attach(ifindex, fd, XDP_FLAGS_REPLACE, &opts))
		fprintf(stderr, "ERROR: attaching xdp program to device\n");

	printf("Press Ctrl-C to stop and unload.\n");
	while (!exiting)
		sleep(300);
}
