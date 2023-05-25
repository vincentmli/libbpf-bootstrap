#include <net/if.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <getopt.h>
#include <sys/types.h>
#include <string.h>
#include <stdnoreturn.h>

#include <bpf/bpf.h>
#include "bpf/libbpf.h"
#include "bpf/btf.h"
#include <linux/if_link.h>

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

static unsigned int ifindex;
static __u32 attached_prog_id;
static __u32 syncookie_prog_id;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void noreturn cleanup(int sig)
{
	LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
	int prog_fd;
	int err;

	if (attached_prog_id == 0)
		exit(0);

	prog_fd = bpf_prog_get_fd_by_id(attached_prog_id);
	if (prog_fd < 0) {
		fprintf(stderr, "Error: bpf_prog_get_fd_by_id: %s\n", strerror(-prog_fd));
		err = bpf_xdp_attach(ifindex, -1, 0, NULL);
		if (err < 0) {
			fprintf(stderr, "Error: bpf_set_link_xdp_fd: %s\n", strerror(-err));
			fprintf(stderr, "Failed to detach XDP program\n");
			exit(1);
		}
	} else {
		opts.old_prog_fd = prog_fd;
		err = bpf_xdp_attach(ifindex, -1, XDP_FLAGS_REPLACE, &opts);
		close(prog_fd);
		if (err < 0) {
			fprintf(stderr, "Error: bpf_set_link_xdp_fd_opts: %s\n", strerror(-err));
			/* Not an error if already replaced by someone else. */
			if (err != -EEXIST) {
				fprintf(stderr, "Failed to detach XDP program\n");
				exit(1);
			}
		}
	}
	exit(0);
}


static noreturn void usage(const char *progname)
{
        fprintf(stderr, "Usage: %s \
        [--iface <iface>|--prog <prog_id>]\n\n \
                        syncookie parameter: \n\n \
                        [--mss4 <mss ipv4>\n \
                        --mss6 <mss ipv6>\n \
                        --wscale <wscale>\n \
                        --ttl <ttl>]\n \
                        [--ports <port1>,<port2>,...]\n \
                        [--single]\n\n \
                        DNS rate limit and cookie parameter: \n\n \
			[--ipv4 <IPv4 V.I.P. pinpath]\n \
			[--ipv6 <IPv6 V.I.P. pinpath]\n \
                        \n",
                progname);
        exit(1);
}

static unsigned long parse_arg_ul(const char *progname, const char *arg, unsigned long limit)
{
        unsigned long res;
        char *endptr;

        errno = 0;
        res = strtoul(arg, &endptr, 10);
        if (errno != 0 || *endptr != '\0' || arg[0] == '\0' || res > limit)
                usage(progname);

        return res;
}

static void parse_options(int argc, char *argv[], unsigned int *ifindex, __u32 *prog_id,
                          __u64 *tcpipopts, char **ports, bool *single)
{
        static struct option long_options[] = {
                { "help", no_argument, NULL, 'h' },
                { "iface", required_argument, NULL, 'i' },
                { "prog", optional_argument, NULL, 'x' },
                { "mss4", optional_argument, NULL, 4 },
                { "mss6", optional_argument, NULL, 6 },
                { "wscale", optional_argument, NULL, 'w' },
                { "ttl", optional_argument, NULL, 't' },
                { "ports", optional_argument, NULL, 'p' },
                { "single", no_argument, NULL, 's' },
                { NULL, 0, NULL, 0 },
        };
        unsigned long mss4, wscale, ttl;
        unsigned long long mss6;
        unsigned int tcpipopts_mask = 0;

        if (argc < 2)
                usage(argv[0]);

        *ifindex = 0;
        *prog_id = 0;
        *tcpipopts = 0;
        *ports = NULL;
        *single = false;

        while (true) {
                int opt;

                opt = getopt_long(argc, argv, "", long_options, NULL);
                if (opt == -1)
                        break;

                switch (opt) {
                case 'h':
                        usage(argv[0]);
                        break;
                case 'i':
                        *ifindex = if_nametoindex(optarg);
                        if (*ifindex == 0)
                                usage(argv[0]);
                        break;
                case 'x':
                        *prog_id = parse_arg_ul(argv[0], optarg, UINT32_MAX);
                        if (*prog_id == 0)
                                usage(argv[0]);
                        break;
                case 4:
                        mss4 = parse_arg_ul(argv[0], optarg, UINT16_MAX);
                        tcpipopts_mask |= 1 << 0;
                        break;
                case 6:
                        mss6 = parse_arg_ul(argv[0], optarg, UINT16_MAX);
                        tcpipopts_mask |= 1 << 1;
                        break;
                case 'w':
                        wscale = parse_arg_ul(argv[0], optarg, 14);
                        tcpipopts_mask |= 1 << 2;
                        break;
                case 't':
                        ttl = parse_arg_ul(argv[0], optarg, UINT8_MAX);
                        tcpipopts_mask |= 1 << 3;
                        break;
                case 'p':
                        *ports = optarg;
                        break;
                case 's':
                        *single = true;
                        break;
                default:
                        usage(argv[0]);
                }
        }
        if (optind < argc)
                usage(argv[0]);

        if (tcpipopts_mask == 0xf) {
                if (mss4 == 0 || mss6 == 0 || wscale == 0 || ttl == 0)
                        usage(argv[0]);
                *tcpipopts = (mss6 << 32) | (ttl << 24) | (wscale << 16) | mss4;
        } else if (tcpipopts_mask != 0) {
                usage(argv[0]);
        }

        if (*ifindex != 0 && *prog_id != 0)
                usage(argv[0]);
        if (*ifindex == 0 && *prog_id == 0)
                usage(argv[0]);
}

static int syncookie_open_bpf_maps(__u32 prog_id, int *values_map_fd, int *ports_map_fd)
{
	struct bpf_prog_info prog_info;
	__u32 map_ids[8];
	__u32 info_len;
	int prog_fd;
	int err;
	int i;

	*values_map_fd = -1;
	*ports_map_fd = -1;

	prog_fd = bpf_prog_get_fd_by_id(prog_id);
	if (prog_fd < 0) {
		fprintf(stderr, "Error: bpf_prog_get_fd_by_id: %s\n", strerror(-prog_fd));
		return prog_fd;
	}

	prog_info = (struct bpf_prog_info) {
		.nr_map_ids = 8,
		.map_ids = (__u64)(unsigned long)map_ids,
	};
	info_len = sizeof(prog_info);

	err = bpf_prog_get_info_by_fd(prog_fd, &prog_info, &info_len);
	if (err != 0) {
		fprintf(stderr, "Error: bpf_prog_get_info_by_fd: %s\n",
			strerror(-err));
		goto out;
	}

	if (prog_info.nr_map_ids < 2) {
		fprintf(stderr, "Error: Found %u BPF maps, expected at least 2\n",
			prog_info.nr_map_ids);
		err = -ENOENT;
		goto out;
	}

	for (i = 0; i < prog_info.nr_map_ids; i++) {
		struct bpf_map_info map_info = {};
		int map_fd;

		err = bpf_map_get_fd_by_id(map_ids[i]);
		if (err < 0) {
			fprintf(stderr, "Error: bpf_map_get_fd_by_id: %s\n", strerror(-err));
			goto err_close_map_fds;
		}
		map_fd = err;

		info_len = sizeof(map_info);
		err = bpf_map_get_info_by_fd(map_fd, &map_info, &info_len);
		if (err != 0) {
			fprintf(stderr, "Error: bpf_map_get_info_by_fd: %s\n",
				strerror(-err));
			close(map_fd);
			goto err_close_map_fds;
		}
		if (strcmp(map_info.name, "values") == 0) {
			*values_map_fd = map_fd;
			continue;
		}
		if (strcmp(map_info.name, "allowed_ports") == 0) {
			*ports_map_fd = map_fd;
			continue;
		}
		close(map_fd);
	}

	if (*values_map_fd != -1 && *ports_map_fd != -1) {
		err = 0;
		goto out;
	}

	err = -ENOENT;

err_close_map_fds:
	if (*values_map_fd != -1)
		close(*values_map_fd);
	if (*ports_map_fd != -1)
		close(*ports_map_fd);
	*values_map_fd = -1;
	*ports_map_fd = -1;

out:
	close(prog_fd);
	return err;
}

static int datasec_map_rewrite(struct xdppacket_bpf *skel, __u16 *ratelimit, __u8 *cpus)
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

static int xdppacket_attach(const char *argv0, unsigned int ifindex)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	struct bpf_prog_info syncookie_info = {};
	__u32 syncookie_info_len = sizeof(syncookie_info);
	int err;

        __u16 ratelimit = DEFAULT_RATELIMIT;
        __u8 cpus = DEFAULT_CPUS;

	int prog_fd;
	int syncookie_prog_fd;

        struct xdppacket_bpf *skel;

        /* Set up libbpf errors and debug info callback */
        libbpf_set_print(libbpf_print_fn);

        /* Load and verify BPF programs*/
        skel = xdppacket_bpf__open_and_load();
        if (!skel) {
                fprintf(stderr, "Failed to open and load skeleton\n");
                return 1;
        }

        //rewrite .data global variable map value
        datasec_map_rewrite(skel, &ratelimit, &cpus);

        prog_fd = bpf_program__fd(skel->progs.xdp_packet);

	err = bpf_prog_get_info_by_fd(prog_fd, &info, &info_len);
	if (err < 0) {
		fprintf(stderr, "Error: bpf_prog_get_info_by_fd: %s\n",
			strerror(-err));
		goto out;
	}
	attached_prog_id = info.id;

        syncookie_prog_fd = bpf_program__fd(skel->progs.syncookie_xdp);

	err = bpf_prog_get_info_by_fd(syncookie_prog_fd, &syncookie_info, &syncookie_info_len);
	if (err < 0) {
		fprintf(stderr, "Error: bpf_prog_get_info_by_fd: %s\n",
			strerror(-err));
		goto out;
	}
	syncookie_prog_id = syncookie_info.id;

	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);

	err = bpf_xdp_attach(ifindex, prog_fd,
		     XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
	if (err < 0) {
		fprintf(stderr, "Error: bpf_set_link_xdp_fd: %s\n",
			strerror(-err));
		goto fail;
	}
	err = 0;
out:
	return err;
fail:
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	attached_prog_id = 0;
	syncookie_prog_id = 0;
	goto out;
}

int main(int argc, char **argv)
{

	/* for syncookie */
	int values_map_fd, ports_map_fd;
	__u64 tcpipopts;
	bool firstiter;
	__u64 prevcnt;
	__u32 prog_id;
	char *ports;
	bool single;
	int err = 0;

	parse_options(argc, argv, &ifindex, &prog_id, &tcpipopts, &ports,
		      &single);

	if (prog_id == 0) {
		err = bpf_xdp_query_id(ifindex, 0, &prog_id);
		if (err < 0) {
			fprintf(stderr, "Error: bpf_get_link_xdp_id: %s\n",
				strerror(-err));
			goto out;
		}
		if (prog_id == 0) {
			err = xdppacket_attach(argv[0], ifindex);
			if (err < 0)
				goto out;
			prog_id = attached_prog_id;
		}
	}

	fprintf(stderr, "XDP attached before map open\n");

	err = syncookie_open_bpf_maps(syncookie_prog_id, &values_map_fd, &ports_map_fd);
	if (err < 0)
		goto out;

	fprintf(stderr, "XDP attached after map open\n");

	if (ports) {
		__u16 port_last = 0;
		__u32 port_idx = 0;
		char *p = ports;

		fprintf(stderr, "Replacing allowed ports\n");

		while (p && *p != '\0') {
			char *token = strsep(&p, ",");
			__u16 port;

			port = parse_arg_ul(argv[0], token, UINT16_MAX);
			err = bpf_map_update_elem(ports_map_fd, &port_idx, &port, BPF_ANY);
			if (err != 0) {
				fprintf(stderr, "Error: bpf_map_update_elem: %s\n", strerror(-err));
				fprintf(stderr, "Failed to add port %u (index %u)\n",
					port, port_idx);
				goto out_close_maps;
			}
			fprintf(stderr, "Added port %u\n", port);
			port_idx++;
		}
		err = bpf_map_update_elem(ports_map_fd, &port_idx, &port_last, BPF_ANY);
		if (err != 0) {
			fprintf(stderr, "Error: bpf_map_update_elem: %s\n", strerror(-err));
			fprintf(stderr, "Failed to add the terminator value 0 (index %u)\n",
				port_idx);
			goto out_close_maps;
		}
	}

	if (tcpipopts) {
		__u32 key = 0;

		fprintf(stderr, "Replacing TCP/IP options\n");

		err = bpf_map_update_elem(values_map_fd, &key, &tcpipopts, BPF_ANY);
		if (err != 0) {
			fprintf(stderr, "Error: bpf_map_update_elem: %s\n", strerror(-err));
			goto out_close_maps;
		}
	}

	if ((ports || tcpipopts) && attached_prog_id == 0 && !single)
		goto out_close_maps;

	prevcnt = 0;
	firstiter = true;

	while (true) {
		__u32 key = 1;
		__u64 value;

		err = bpf_map_lookup_elem(values_map_fd, &key, &value);
		if (err != 0) {
			fprintf(stderr, "Error: bpf_map_lookup_elem: %s\n", strerror(-err));
			goto out_close_maps;
		}
		if (firstiter) {
			prevcnt = value;
			firstiter = false;
		}
		if (single) {
			printf("Total SYNACKs generated: %llu\n", value);
			break;
		}

		printf("SYNACKs generated: %llu (total %llu)\n", value - prevcnt, value);
		prevcnt = value;
		sleep(300);
	}

	printf("Press Ctrl-C to stop and unload.\n");

out_close_maps:
	close(values_map_fd);
	close(ports_map_fd);
out:
	return err == 0 ? 0 : 1;
}
