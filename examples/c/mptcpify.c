// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright 2026 LoongFire */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "mptcpify.skel.h"
#include "mptcpify.h"  // ADD THIS LINE!

static volatile bool exiting = false;

typedef enum {
    MODE_ALL,      // Force all applications
    MODE_TARGETS,  // Specific target applications
    MODE_PIDS      // Specific PIDs
} work_mode_t;

struct env {
    work_mode_t mode;
    char **targets;      // For MODE_TARGETS
    pid_t *pids;         // For MODE_PIDS  
    int target_count;
    bool verbose;
} env = {
    .mode = MODE_ALL,
    .targets = NULL,
    .pids = NULL,
    .target_count = 0,
    .verbose = false
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
    exiting = true;
}

static void print_usage(const char *prog_name)
{
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("Force applications to use MPTCP instead of TCP\n\n");
    printf("Options:\n");
    printf("  -t, --targets COMMA_SEPARATED_LIST   Target applications by name\n");
    printf("  -p, --pids COMMA_SEPARATED_LIST      Target applications by PID\n");
    printf("  -v, --verbose                        Verbose output\n");
    printf("  -h, --help                           Show this help\n\n");
    printf("Examples:\n");
    printf("  %s                           # Force MPTCP for all applications\n", prog_name);
    printf("  %s -t curl,wget             # Force MPTCP only for curl and wget\n", prog_name);
    printf("  %s -p 1234,5678             # Force MPTCP for PIDs 1234 and 5678\n", prog_name);
    printf("  %s -t curl -p 9999          # Combined mode\n", prog_name);
}

static int parse_comma_list(const char *str, char ***items, int *count)
{
    char *copy, *token, *saveptr;
    int item_count = 0;
    
    if (!str || !*str)
        return 0;
    
    // Count items
    copy = strdup(str);
    if (!copy)
        return -1;
    
    token = strtok_r(copy, ",", &saveptr);
    while (token) {
        item_count++;
        token = strtok_r(NULL, ",", &saveptr);
    }
    free(copy);
    
    if (item_count == 0)
        return 0;
    
    // Allocate array
    *items = calloc(item_count, sizeof(char *));
    if (!*items)
        return -1;
    
    // Parse items
    copy = strdup(str);
    if (!copy) {
        free(*items);
        *items = NULL;
        return -1;
    }
    
    *count = 0;
    token = strtok_r(copy, ",", &saveptr);
    while (token && *count < item_count) {
        // Trim whitespace
        while (*token && isspace(*token)) token++;
        char *end = token + strlen(token) - 1;
        while (end > token && isspace(*end)) *end-- = '\0';
        
        (*items)[*count] = strdup(token);
        if (!(*items)[*count]) {
            for (int i = 0; i < *count; i++) free((*items)[i]);
            free(*items);
            free(copy);
            *items = NULL;
            return -1;
        }
        (*count)++;
        token = strtok_r(NULL, ",", &saveptr);
    }
    
    free(copy);
    return 0;
}

static int parse_pid_list(const char *str, pid_t **pids, int *count)
{
    char **items = NULL;
    int item_count = 0;
    int ret = 0;
    
    ret = parse_comma_list(str, &items, &item_count);
    if (ret < 0)
        return ret;
    
    if (item_count == 0)
        return 0;
    
    *pids = calloc(item_count, sizeof(pid_t));
    if (!*pids) {
        for (int i = 0; i < item_count; i++) free(items[i]);
        free(items);
        return -1;
    }
    
    for (int i = 0; i < item_count; i++) {
        char *endptr;
        (*pids)[i] = strtol(items[i], &endptr, 10);
        if (*endptr != '\0') {
            // Invalid PID
            fprintf(stderr, "Invalid PID: %s\n", items[i]);
            ret = -1;
        }
        free(items[i]);
    }
    
    *count = item_count;
    free(items);
    return ret;
}

static void cleanup_env(void)
{
    if (env.targets) {
        for (int i = 0; i < env.target_count; i++) {
            if (env.targets[i]) free(env.targets[i]);
        }
        free(env.targets);
        env.targets = NULL;
    }
    
    if (env.pids) {
        free(env.pids);
        env.pids = NULL;
    }
    
    env.target_count = 0;
}

int main(int argc, char **argv)
{
    struct mptcpify_bpf *skel = NULL;
    int err = 0;
    int mode_key = 0;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            env.verbose = true;
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--targets") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: Missing argument for -t/--targets\n");
                return 1;
            }
            env.mode = MODE_TARGETS;
            if (parse_comma_list(argv[++i], &env.targets, &env.target_count) < 0) {
                fprintf(stderr, "Error: Failed to parse target list\n");
                return 1;
            }
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--pids") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: Missing argument for -p/--pids\n");
                return 1;
            }
            env.mode = MODE_PIDS;
            if (parse_pid_list(argv[++i], &env.pids, &env.target_count) < 0) {
                fprintf(stderr, "Error: Failed to parse PID list\n");
                return 1;
            }
        } else {
            fprintf(stderr, "Error: Unknown option '%s'\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // Set up libbpf
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);
    
    // Open and load BPF program
    skel = mptcpify_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        err = 1;
        goto cleanup;
    }
    
    // Set work mode
    int mode_value = (env.mode == MODE_ALL) ? 0 : 1;
    int work_mode_fd = bpf_map__fd(skel->maps.work_mode);
    err = bpf_map_update_elem(work_mode_fd, &mode_key, &mode_value, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to set work mode: %d\n", err);
        goto cleanup;
    }
    
    // Populate target maps based on mode
    if (env.mode == MODE_TARGETS && env.targets) {
        int target_apps_fd = bpf_map__fd(skel->maps.target_apps);
        
        for (int i = 0; i < env.target_count; i++) {
            struct app_name name = {};
            int value = 1;
            
            strncpy(name.str, env.targets[i], TASK_COMM_LEN - 1);
            name.str[TASK_COMM_LEN - 1] = '\0';
            
            err = bpf_map_update_elem(target_apps_fd, &name, &value, BPF_ANY);
            if (err) {
                fprintf(stderr, "Failed to add target '%s': %d\n", env.targets[i], err);
                goto cleanup;
            }
        }
        
        printf("MPTCP is being forced for [");
        for (int i = 0; i < env.target_count; i++) {
            printf("%s%s", env.targets[i], i < env.target_count - 1 ? ", " : "");
        }
        printf("]\n");
        
    } else if (env.mode == MODE_PIDS && env.pids) {
        int target_pids_fd = bpf_map__fd(skel->maps.target_pids);
        
        for (int i = 0; i < env.target_count; i++) {
            __u32 key = env.pids[i];
            __u32 value = 1;
            
            err = bpf_map_update_elem(target_pids_fd, &key, &value, BPF_ANY);
            if (err) {
                fprintf(stderr, "Failed to add PID %d: %d\n", env.pids[i], err);
                goto cleanup;
            }
        }
        
        printf("MPTCP is being forced for PIDs [");
        for (int i = 0; i < env.target_count; i++) {
            printf("%d%s", env.pids[i], i < env.target_count - 1 ? ", " : "");
        }
        printf("]\n");
        
    } else {
        printf("MPTCP is being forced for all applications\n");
    }
    
    // Attach BPF program
    err = mptcpify_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        fprintf(stderr, "Possible reasons:\n");
        fprintf(stderr, "  1. Kernel doesn't support fmod_ret (needs 5.7+)\n");
        fprintf(stderr, "  2. 'update_socket_protocol' hook not available\n");
        fprintf(stderr, "  3. Missing CAP_BPF capability\n");
        goto cleanup;
    }
    
    // Set up signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    printf("Press Ctrl+C to exit...\n");
    
    // Wait for exit signal
    while (!exiting) {
        sleep(1);
    }
    
    printf("\nExiting...\n");
    
cleanup:
    // Cleanup
    cleanup_env();
    
    if (skel)
        mptcpify_bpf__destroy(skel);
    
    return err < 0 ? -err : err;
}
