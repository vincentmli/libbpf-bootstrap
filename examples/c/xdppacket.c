#include <net/if.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <bpf/bpf.h>

#include "bpf/libbpf.h"
#include "bpf/btf.h"
#include "xdppacket.skel.h"

#define IFINDEX_LO 1
#define XDP_FLAGS_REPLACE		(1U << 4)

#ifndef DEFAULT_IFACE
#define DEFAULT_IFACE "lo"
#endif
#define DEFAULT_IPv4_VIP_PINPATH "/sys/fs/bpf/rrl_exclude_v4_prefixes"
#define DEFAULT_IPv6_VIP_PINPATH "/sys/fs/bpf/rrl_exclude_v6_prefixes"
#define DEFAULT_RATELIMIT 0x20
#define DEFAULT_CPUS 0x2

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

static int datasec_map_rewrite(struct xdppacket_bpf *skel, unsigned int *ratelimit, unsigned int *cpus)
{
	struct bpf_map *map;
	struct btf *btf;
	const struct btf_type *datasec;
	struct btf_var_secinfo *infos;
	int map_fd;
	__s32 datasec_id;
	int zero = 0;
	int i, err;
	size_t sz;
	__u8 *buff = NULL;

	map = bpf_object__find_map_by_name(skel->obj, ".data");
	if (!map) {
		fprintf(stderr, "Failed to find .data \n");
		return 1;
	}

	map_fd = bpf_map__fd(map);
	if (!map_fd) {
		fprintf(stderr, "Failed to find .data map_fd\n");
		return 1;
	}

	// Create buffer the size of .data
	sz = bpf_map__value_size(map);
	buff = malloc(sz);
	if (!buff)
		return 1;

	// Read .data into the buffer
	err = bpf_map_lookup_elem(map_fd, &zero, buff);
	if (err)
		return 1;

	// Get BTF, we need it do find out the memory layout of .data
	btf = bpf_object__btf(skel->obj);
	if (libbpf_get_error(btf)) {
		fprintf(stderr, "Failed to find obj btf\n");
		return 1;
	}

	// Get the type ID of the datasection of .data
	datasec_id = btf__find_by_name(btf, ".data");
	if (!datasec_id) {
		fprintf(stderr, "Failed to find btf datasec_id\n");
		return 1;
	}

	// Get the actual BTF type from the ID
	datasec = btf__type_by_id(btf, datasec_id);
	if (libbpf_get_error(datasec)) {
		fprintf(stderr, "Failed to find btf datasec\n");
		return 1;
	}
	// Get all secinfos, each of which will be a global variable
	infos = btf_var_secinfos(datasec);
	// Loop over all sections
	for(i = 0; i < btf_vlen(datasec); i++) {
		// Get the BTF type of the current var
		const struct btf_type *t = btf__type_by_id(btf, infos[i].type);
		// Get the name of the global variable
		const char *name = btf__name_by_offset(btf, t->name_off);
		// If it matches the name of the var we want to change at runtime
            // Overwrite its value (this code assumes just a single byte)
            // for multibyte values you will obviusly have to edit more bytes.
            // the total size of the var can be gotten from infos[i]->size, use
	    // memcpy for multiple bytes
		if (!strcmp(name, "ratelimit")) {
			memcpy(&buff[infos[i].offset], ratelimit, buff[infos[i].size]);
		} else if (!strcmp(name, "numcpus")) {
			memcpy(&buff[infos[i].offset], cpus, buff[infos[i].size]);
		}
	}

    // Write the updated datasection to the map
	err = bpf_map_update_elem(map_fd, &zero, buff, 0);
	//here returns negative value, but the map value is updated
	if (err) {
		fprintf(stderr, "Failed to update .data map : %d\n", err);
		return err;
	}

	free(buff);

	return 0;
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
	struct xdppacket_bpf *skel;

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
			ratelimit = atoi(optarg);
			break;
		case 'c':
			cpus = atoi(optarg);
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
	skel = xdppacket_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load skeleton\n");
		return 1;
	}

	//rewrite .data global variable map value
	datasec_map_rewrite(skel, &ratelimit, &cpus);

	fd = bpf_program__fd(skel->progs.xdp_packet);

	if (bpf_xdp_attach(ifindex, fd, XDP_FLAGS_REPLACE, &opts))
		fprintf(stderr, "ERROR: attaching xdp program to device\n");

	printf("Press Ctrl-C to stop and unload.\n");
	while (!exiting)
		sleep(300);
}
