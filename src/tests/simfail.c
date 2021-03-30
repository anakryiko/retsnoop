// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "tests/kprobe_bad_kfunc.skel.h"
#include "tests/fentry_unsupp_func.skel.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

static struct env {
	bool verbose;
	bool list;
	bool all;
	const char *case_names[64];
	int case_cnt;
} env;

const char *argp_program_version = "simfail 0.0";
const char *argp_program_bug_address = "Andrii Nakryiko <andrii@kernel.org>";
const char argp_program_doc[] =
"A set of various kernel failure simulators for retsnoop testing/demo.\n"
"\n"
"USAGE: ./simfail [-v] [-a] [-l] [CASE]*\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose mode" },
	{ "all", 'a', NULL, 0, "Simulate all available failure scenarios" },
	{ "list", 'l', NULL, 0, "Only list all available failure scenarios" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'a':
		env.all = true;
		break;
	case 'l':
		env.list = true;
		break;
	case ARGP_KEY_ARG:
		env.case_names[env.case_cnt++] = arg;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (!env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static int bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		return -errno;
	}

	return 0;
}

enum {
	BAD_MAP_TYPE,
	BAD_MAP_CREATE_FLAGS,
	BAD_MAP_KEY_SIZE_ARRAY,
	BAD_MAP_KEY_SIZE_STACKMAP,
	BAD_MAP_KEY_SIZE_PERFBUF,
	BAD_MAP_KEY_SIZE_RINGBUF,
	BAD_MAP_VAL_SIZE_PERCPU_ARRAY,
	BAD_MAP_MAX_ENTRIES_ARRAY,
	BAD_MAP_MAX_ENTRIES_RINGBUF,
	BAD_MAP_LOOKUP_KEY,
	BAD_MAP_LOOKUP_VALUE,
	BAD_MAP_LOOKUP_FLAGS,
};

static int PAGE_SIZE;

static void fail_bpf_bad_map(long arg)
{
	int fd;
	int map_type = BPF_MAP_TYPE_ARRAY;
	int key_size = 4;
	int val_size = 4;
	int max_entries = 1;
	int map_flags = 0, lookup_flags = 0;
	void *key_ptr = &key_size, *val_ptr = &val_size;
	bool do_lookup = false;

	switch (arg) {
	case BAD_MAP_TYPE:
		map_type = -1;
		break;
	case BAD_MAP_CREATE_FLAGS:
		map_flags = -1;
		break;
	case BAD_MAP_KEY_SIZE_ARRAY:
		key_size = 8; /* should be 4 */
		break;
	case BAD_MAP_KEY_SIZE_STACKMAP:
		map_type = BPF_MAP_TYPE_STACK_TRACE;
		key_size = 8; /* should be 4 */
		break;
	case BAD_MAP_KEY_SIZE_RINGBUF:
		map_type = BPF_MAP_TYPE_RINGBUF;
		key_size = 1; /* should be 0 */
		val_size = 0;
		max_entries = PAGE_SIZE;
		break;
	case BAD_MAP_VAL_SIZE_PERCPU_ARRAY:
		map_type = BPF_MAP_TYPE_PERCPU_ARRAY;
		/* overall amount of per-cpu data is too big */
		val_size = 1 * 1024 * 1024;
		max_entries = 1024;
		break;
	case BAD_MAP_MAX_ENTRIES_ARRAY:
		max_entries = 0; /* should be positive */
		break;
	case BAD_MAP_MAX_ENTRIES_RINGBUF:
		map_type = BPF_MAP_TYPE_RINGBUF;
		key_size = 0;
		val_size = 0;
		max_entries = PAGE_SIZE - 1; /* should be multiple of PAGE_SIZE */
		break;
	case BAD_MAP_LOOKUP_KEY:
		key_ptr = NULL; /* should be valid pointer to key_size bytes */
		do_lookup = true;
		break;
	case BAD_MAP_LOOKUP_VALUE:
		val_ptr = NULL; /* should be valid pointer to val_size bytes */
		do_lookup = true;
		break;
	}

	fd = bpf_create_map(map_type, key_size, val_size, max_entries, map_flags);
	if (do_lookup)
		bpf_map_lookup_elem_flags(fd, key_ptr, val_ptr, lookup_flags);
	close(fd);
}

void fail_bpf_kprobe_bad_kfunc(long arg)
{
	struct kprobe_bad_kfunc_bpf *skel;

	skel = kprobe_bad_kfunc_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open/load kprobe_bad_kfunc_bpf skeleton!\n");
		return;
	}
	kprobe_bad_kfunc_bpf__attach(skel); /* should fail */
	kprobe_bad_kfunc_bpf__destroy(skel);
}

void fail_bpf_fentry_unsupp_func(long arg)
{
	struct fentry_unsupp_func_bpf *skel;

	skel = fentry_unsupp_func_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open/load kprobe_bad_kfunc_bpf skeleton!\n");
		return;
	}
	fentry_unsupp_func_bpf__attach(skel); /* should fail */
	fentry_unsupp_func_bpf__destroy(skel);
}

struct case_desc {
	const char *subsys;
	const char *name;
	void (*func)(long);
	long arg;
	const char *desc;
} cases[] = {
	{ "bpf","bpf-bad-map-type", fail_bpf_bad_map, BAD_MAP_TYPE,
	  "Pass bad BPF map type to BPF_MAP_CREATE" },
	{ "bpf","bpf-bad-map-create-flags", fail_bpf_bad_map, BAD_MAP_CREATE_FLAGS,
	  "Pass bad BPF map flags to BPF_MAP_CREATE" },
	{ "bpf","bpf-bad-map-key-size-array", fail_bpf_bad_map, BAD_MAP_KEY_SIZE_ARRAY,
	  "Pass bad BPF map key size for ARRAY map" },
	{ "bpf","bpf-bad-map-key-size-stackmap", fail_bpf_bad_map, BAD_MAP_KEY_SIZE_STACKMAP,
	  "Pass bad BPF map key size for STACK_TRACE map" },
	{ "bpf","bpf-bad-map-key-size-ringbuf", fail_bpf_bad_map, BAD_MAP_KEY_SIZE_RINGBUF,
	  "Pass bad BPF map key size for RINGBUF map" },
	{ "bpf","bpf-bad-map-val-size-percpu-array", fail_bpf_bad_map, BAD_MAP_VAL_SIZE_PERCPU_ARRAY,
	  "Pass bad BPF map value size (too big) for PERCPU_ARRAY map" },
	{ "bpf","bpf-bad-map-max-entries-array", fail_bpf_bad_map, BAD_MAP_MAX_ENTRIES_ARRAY,
	  "Pass bad BPF map max entries for ARRAY map" },
	{ "bpf","bpf-bad-map-max-entries-ringbuf", fail_bpf_bad_map, BAD_MAP_MAX_ENTRIES_RINGBUF,
	  "Pass bad BPF map max entries for RINGBUF map" },
	{ "bpf","bpf-bad-map-lookup-key", fail_bpf_bad_map, BAD_MAP_LOOKUP_KEY,
	  "Pass bad BPF map key pointer on lookup" },
	{ "bpf","bpf-bad-map-lookup-value", fail_bpf_bad_map, BAD_MAP_LOOKUP_VALUE,
	  "Pass bad BPF map value pointer on lookup" },

	{ "bpf","bpf-kprobe-bad-kfunc", fail_bpf_kprobe_bad_kfunc, 0,
	  "Attempt to attach kprobe BPF program to not existing kfunc" },
	{ "bpf","bpf-fentry-unsupp-func", fail_bpf_fentry_unsupp_func, 0,
	  "Attempt to attach fentry BPF program to unsupported function" },
};

int main(int argc, char **argv)
{
	bool memlock_bumped = false;
	int err, i, j, n;

	PAGE_SIZE = sysconf(_SC_PAGESIZE);

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	n = env.all ? ARRAY_SIZE(cases) : env.case_cnt;
	if (n == 0) {
		fprintf(stderr, "No cases specified, please use -a or list case names.\n");
		return 1;
	}
	for (i = 0; i < n; i++) {
		struct case_desc *c = NULL;

		if (env.all) {
			c = &cases[i];
		} else {
			for (j = 0; j < ARRAY_SIZE(cases); j++) {
				if (strcmp(env.case_names[i], cases[j].name) == 0) {
					c = &cases[j];
					break;
				}
			}
			if (!c) {
				fprintf(stderr, "Case '%s' doesn't exist.\n", env.case_names[i]);
				return 1;
			}
		}

		if (env.list) {
			printf("[%s] %s: %s\n", c->subsys, c->name, c->desc);
			continue;
		}

		if (strcmp(c->subsys, "bpf") == 0 && !memlock_bumped) {
			err = bump_memlock_rlimit();
			if (err) {
				fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK, exiting!\n");
				return 2;
			}
			memlock_bumped = true;
		}

		if (env.verbose)
			printf("EXECUTING CASE [%s] '%s'...\n", c->subsys, c->name);
		c->func(c->arg);
	}

	return 0;
}
