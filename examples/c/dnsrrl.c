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

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	int fd;
	LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
	struct dnsrrl_bpf *skel;

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

	fd = bpf_program__fd(skel->progs.dns_rrl);

	if (bpf_xdp_attach(IFINDEX_LO, fd, XDP_FLAGS_REPLACE, &opts))
		fprintf(stderr, "ERROR: attaching xdp program to device\n");

	printf("Press Ctrl-C to stop and unload.\n");
	while (!exiting)
		sleep(300);
}
