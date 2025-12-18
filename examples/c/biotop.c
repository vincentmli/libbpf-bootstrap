// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

/*
 * biotop Trace block I/O by process.
 * Copyright (c) 2022 Francis Laniel <flaniel@linux.microsoft.com>
 *
 * Based on biotop(8) from BCC by Brendan Gregg.
 * 03-Mar-2022   Francis Laniel   Created this.
 * 23-Nov-2023   Pcheng Cui       Add PID filter support.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "biotop.h"
#include "biotop.skel.h"
#include "compat.h"
#include "trace_helpers.h"
#include "map_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define OUTPUT_ROWS_LIMIT 10240

enum SORT {
	ALL,
	IO,
	BYTES,
	TIME,
};

struct disk {
	int major;
	int minor;
	char name[256];
};

struct vector {
	size_t nr;
	size_t capacity;
	void **elems;
};

int grow_vector(struct vector *vector) {
	if (vector->nr >= vector->capacity) {
		void **reallocated;

		if (!vector->capacity)
			vector->capacity = 1;
		else
			vector->capacity *= 2;

		reallocated = libbpf_reallocarray(vector->elems, vector->capacity, sizeof(*vector->elems));
		if (!reallocated)
			return -1;

		vector->elems = reallocated;
	}

	return 0;
}

void free_vector(struct vector vector) {
	for (size_t i = 0; i < vector.nr; i++)
		if (vector.elems[i] != NULL)
			free(vector.elems[i]);
	free(vector.elems);
}

struct vector disks = {0, 0, NULL};  // Explicit initialization

static volatile sig_atomic_t exiting = 0;

static bool clear_screen = true;
static int output_rows = 20;
static int sort_by = ALL;
static int interval = 1;
static int count = 99999999;
static pid_t target_pid = 0;
static bool verbose = false;

void print_usage(char *prog_name) {
    printf("Usage: %s [options] [interval] [count]\n", prog_name);
    printf("Trace file reads/writes by process.\n");
    printf("\n");
    printf("Options:\n");
    printf("  -C, --noclear       Don't clear the screen\n");
    printf("  -s, --sort SORT     Sort columns, default all [all, io, bytes, time]\n");
    printf("  -r, --rows ROWS     Maximum rows to print, default 20\n");
    printf("  -p, --pid PID       Process ID to trace\n");
    printf("  -v, --verbose       Verbose debug output\n");
    printf("  -h, --help          Display this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s                  # file I/O top, refresh every 1s\n", prog_name);
    printf("  %s 5 10            # 5s summaries, 10 times\n", prog_name);
    printf("  %s -p 181          # only trace PID 1216\n", prog_name);
    printf("\n");
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

struct data_t {
	struct info_t key;
	struct val_t value;
};

static int sort_column(const void *obj1, const void *obj2)
{
	struct data_t *d1 = (struct data_t *) obj1;
	struct data_t *d2 = (struct data_t *) obj2;

	struct val_t *s1 = &d1->value;
	struct val_t *s2 = &d2->value;

	if (sort_by == IO)
		return s2->io - s1->io;
	else if (sort_by == BYTES)
		return s2->bytes - s1->bytes;
	else if (sort_by == TIME)
		return s2->us - s1->us;
	else
		return (s2->io + s2->bytes + s2->us)
			- (s1->io + s1->bytes + s1->us);
}

static void parse_disk_stat(void)
{
	FILE *fp;
	char *line = NULL;
	size_t zero = 0;

	fp = fopen("/proc/diskstats", "r");
	if (!fp)
		return;

	while (getline(&line, &zero, fp) != -1) {
		struct disk disk;

		if (sscanf(line, "%d %d %s", &disk.major, &disk.minor, disk.name) != 3)
			continue;

		if (grow_vector(&disks) == -1)
			goto err;

		disks.elems[disks.nr] = malloc(sizeof(disk));
		if (!disks.elems[disks.nr])
			goto err;

		memcpy(disks.elems[disks.nr], &disk, sizeof(disk));

		disks.nr++;
	}

	free(line);
	fclose(fp);

	return;
err:
	fprintf(stderr, "realloc or malloc failed\n");
	free(line);
	if (fp) fclose(fp);
	free_vector(disks);
}

static char *search_disk_name(int major, int minor)
{
	for (size_t i = 0; i < disks.nr; i++) {
		struct disk *diskp;

		if (!disks.elems[i])
			continue;

		diskp = (struct disk *) disks.elems[i];
		if (diskp->major == major && diskp->minor == minor)
			return diskp->name;
	}

	return "";
}

static int read_stat(struct biotop_bpf *obj, struct data_t *datas, __u32 *count)
{
	struct info_t keys[OUTPUT_ROWS_LIMIT];
	struct val_t values[OUTPUT_ROWS_LIMIT];
	struct info_t invalid_key = {0};
	int fd = bpf_map__fd(obj->maps.counts);
	int err, i;

	err = dump_hash(fd, keys, sizeof(struct info_t), values, sizeof(struct val_t),
			count, &invalid_key, true /* lookup_and_delete */);
	if (err)
		return err;

	/* Store data in datas array */
	for (i = 0; i < *count; i++) {
		datas[i].key = keys[i];
		datas[i].value = values[i];
	}

	return 0;
}

static int print_stat(struct biotop_bpf *obj)
{
	FILE *f;
	time_t t;
	struct tm *tm;
	char ts[16], buf[256];
	static struct data_t datas[OUTPUT_ROWS_LIMIT];
	int n, i, err = 0, rows = OUTPUT_ROWS_LIMIT;

	f = fopen("/proc/loadavg", "r");
	if (f) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		memset(buf, 0, sizeof(buf));
		n = fread(buf, 1, sizeof(buf), f);
		if (n)
			printf("%8s loadavg: %s\n", ts, buf);
		fclose(f);
	}
	printf("%-7s %-16s %1s %-3s %-3s %-8s %5s %7s %6s\n",
	       "PID", "COMM", "D", "MAJ", "MIN", "DISK", "I/O", "Kbytes", "AVGms");

	err = read_stat(obj, datas, (__u32*) &rows);
	if (err) {
		fprintf(stderr, "read stat failed: %s\n", strerror(errno));
		return err;
	}

	qsort(datas, rows, sizeof(struct data_t), sort_column);
	rows = rows < output_rows ? rows : output_rows;
	for (i = 0; i < rows; i++) {
		int major;
		int minor;
		struct info_t *key = &datas[i].key;
		struct val_t *value = &datas[i].value;
		float avg_ms = 0;

		/* To avoid floating point exception. */
		if (value->io)
			avg_ms = ((float) value->us) / 1000 / value->io;

		major = key->major;
		minor = key->minor;

		printf("%-7d %-16s %1s %-3d %-3d %-8s %5d %7lld %6.2f\n",
		       key->pid, key->name, key->rwflag ? "W": "R",
		       major, minor, search_disk_name(major, minor),
		       value->io, value->bytes / 1024, avg_ms);
	}

	printf("\n");
	return err;
}

static bool has_block_io_tracepoints(void)
{
	return tracepoint_exists("block", "block_io_start") &&
		tracepoint_exists("block", "block_io_done");
}

static void disable_block_io_tracepoints(struct biotop_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.block_io_start, false);
	bpf_program__set_autoload(obj->progs.block_io_done, false);
}

static void disable_blk_account_io_kprobes(struct biotop_bpf *obj)
{
	bpf_program__set_autoload(obj->progs.blk_account_io_start, false);
	bpf_program__set_autoload(obj->progs.blk_account_io_done, false);
	bpf_program__set_autoload(obj->progs.__blk_account_io_start, false);
	bpf_program__set_autoload(obj->progs.__blk_account_io_done, false);
}

static void blk_account_io_set_autoload(struct biotop_bpf *obj,
					struct ksyms *ksyms)
{
	if (!ksyms__get_symbol(ksyms, "__blk_account_io_start")) {
		bpf_program__set_autoload(obj->progs.__blk_account_io_start, false);
		bpf_program__set_autoload(obj->progs.__blk_account_io_done, false);
	} else {
		bpf_program__set_autoload(obj->progs.blk_account_io_start, false);
		bpf_program__set_autoload(obj->progs.blk_account_io_done, false);
	}
}

int main(int argc, char **argv)
{
	static struct option long_options[] = {
		{"noclear", no_argument, 0, 'C'},
		{"sort", required_argument, 0, 's'},
		{"rows", required_argument, 0, 'r'},
		{"pid", required_argument, 0, 'p'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};
	struct biotop_bpf *obj;
	struct ksyms *ksyms;
	int err = 0;
	int opt;
	int pos_args = 0;
	
	// Parse command line options
	while ((opt = getopt_long(argc, argv, "Cs:r:p:vh", long_options, NULL)) != -1) {
		long rows, pid;
		
		switch (opt) {
		case 'C':
			clear_screen = false;
			break;
		case 's':
			if (!strcmp(optarg, "all")) {
				sort_by = ALL;
			} else if (!strcmp(optarg, "io")) {
				sort_by = IO;
			} else if (!strcmp(optarg, "bytes")) {
				sort_by = BYTES;
			} else if (!strcmp(optarg, "time")) {
				sort_by = TIME;
			} else {
				warn("invalid sort method: %s\n", optarg);
				print_usage(argv[0]);
				return 1;
			}
			break;
		case 'r':
			errno = 0;
			rows = strtol(optarg, NULL, 10);
			if (errno || rows <= 0) {
				warn("invalid rows: %s\n", optarg);
				print_usage(argv[0]);
				return 1;
			}
			output_rows = rows;
			if (output_rows > OUTPUT_ROWS_LIMIT)
				output_rows = OUTPUT_ROWS_LIMIT;
			break;
		case 'p':
			errno = 0;
			pid = strtol(optarg, NULL, 10);
			if (errno || pid <= 0) {
				warn("Invalid PID: %s\n", optarg);
				print_usage(argv[0]);
				return 1;
			}
			target_pid = pid;
			break;
		case 'v':
			verbose = true;
			break;
		case 'h':
			print_usage(argv[0]);
			return 0;
		case '?':
			// getopt already printed an error message
			print_usage(argv[0]);
			return 1;
		default:
			warn("unexpected option\n");
			print_usage(argv[0]);
			return 1;
		}
	}
	
	// Parse positional arguments
	for (int i = optind; i < argc; i++) {
		errno = 0;
		if (pos_args == 0) {
			interval = strtol(argv[i], NULL, 10);
			if (errno || interval <= 0) {
				warn("invalid interval\n");
				print_usage(argv[0]);
				return 1;
			}
		} else if (pos_args == 1) {
			count = strtol(argv[i], NULL, 10);
			if (errno || count <= 0) {
				warn("invalid count\n");
				print_usage(argv[0]);
				return 1;
			}
		} else {
			warn("unrecognized positional argument: %s\n", argv[i]);
			print_usage(argv[0]);
			return 1;
		}
		pos_args++;
	}

	// Set libbpf print callback early
	libbpf_set_print(libbpf_print_fn);

	// Initialize disks vector
	disks.nr = 0;
	disks.capacity = 0;
	disks.elems = NULL;

	// Parse disk stats before opening BPF object
	parse_disk_stat();

	obj = biotop_bpf__open();
	if (!obj) {
		warn("failed to open BPF object\n");
		free_vector(disks);
		return 1;
	}

	obj->rodata->target_pid = target_pid;

	ksyms = ksyms__load();
	if (!ksyms) {
		err = -ENOMEM;
		warn("failed to load kallsyms\n");
		goto cleanup;
	}

	if (has_block_io_tracepoints())
		disable_blk_account_io_kprobes(obj);
	else {
		disable_block_io_tracepoints(obj);
		blk_account_io_set_autoload(obj, ksyms);
	}

	err = biotop_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = biotop_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (1) {
		sleep(interval);

		if (clear_screen) {
			err = system("clear");
			if (err)
				goto cleanup;
		}

		err = print_stat(obj);
		if (err)
			goto cleanup;

		count--;
		if (exiting || !count)
			goto cleanup;
	}

cleanup:
	ksyms__free(ksyms);
	free_vector(disks);
	if (obj)
		biotop_bpf__destroy(obj);

	return err != 0;
}
