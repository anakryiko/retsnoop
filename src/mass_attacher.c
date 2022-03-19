// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2021 Facebook */
#include <errno.h>
#include <stdbool.h>
#include <bpf/btf.h>
#include <bpf/bpf.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <unistd.h>
#include "mass_attacher.h"
#include "ksyms.h"
#include "calib_feat.skel.h"

#ifndef SKEL_NAME
#error "Please define -DSKEL_NAME=<BPF skeleton name> for mass_attacher"
#endif
#ifndef SKEL_HEADER
#error "Please define -DSKEL_HEADER=<path to .skel.h> for mass_attacher"
#endif

#define ____resolve(x) #x
#define ___resolve(x) ____resolve(x)

/* Some skeletons expect common (between BPF and user-space parts of the
 * application) header with extra types. SKEL_EXTRA_HEADER, if specified, will
 * be included to get those types defined to make it possible to compile full
 * BPF skeleton definition properly.
 */
#ifdef SKEL_EXTRA_HEADER
#include ___resolve(SKEL_EXTRA_HEADER)
#endif
#include ___resolve(SKEL_HEADER)

#define ___concat(a, b) a ## b
#define ___apply(fn, n) ___concat(fn, n)

#define SKEL_LOAD(skel) ___apply(SKEL_NAME, __load)(skel)
#define SKEL_ATTACH(skel) ___apply(SKEL_NAME, __attach)(skel)
#define SKEL_DESTROY(skel) ___apply(SKEL_NAME, __destroy)(skel)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

static const char *enforced_deny_globs[] = {
	/* we use it for recursion protection */
	"bpf_get_smp_processor_id",

	/* low-level delicate functions */
	"migrate_enable",
	"migrate_disable",
	"rcu_read_lock*",
	"rcu_read_unlock*",
	"__bpf_prog_enter*",
	"__bpf_prog_exit*",
};

/* For older kernels with fexit crashing on long-sleeping functions,
 * avoid attaching to them unless kernel has
 * e21aa341785c ("bpf: Fix fexit trampoline."), fixing the issue.
 */
static const char *sleepable_deny_globs[] = {
	"*_sys_select",
	"*_sys_pselect6*",
	"*_sys_epoll_wait",
	"*_sys_epoll_pwait",
	"*_sys_poll*",
	"*_sys_ppoll*",
	"*_sys_nanosleep*",
	"*_sys_clock_nanosleep*",
};

#define MAX_FUNC_ARG_CNT 6

struct mass_attacher;

static _Thread_local struct mass_attacher *cur_attacher;

struct kprobe_info {
	char *name;
	bool used;
};

struct mass_attacher {
	struct ksyms *ksyms;
	struct btf *vmlinux_btf;
	struct SKEL_NAME *skel;

	struct bpf_program *fentries[MAX_FUNC_ARG_CNT + 1];
	struct bpf_program *fexits[MAX_FUNC_ARG_CNT + 1];
	struct bpf_insn *fentries_insns[MAX_FUNC_ARG_CNT + 1];
	struct bpf_insn *fexits_insns[MAX_FUNC_ARG_CNT + 1];
	size_t fentries_insn_cnts[MAX_FUNC_ARG_CNT + 1];
	size_t fexits_insn_cnts[MAX_FUNC_ARG_CNT + 1];

	bool use_fentries;
	bool verbose;
	bool debug;
	bool debug_extra;
	bool dry_run;
	int max_func_cnt;
	int max_fileno_rlimit;
	func_filter_fn func_filter;

	int kret_ip_off;
	bool has_bpf_get_func_ip;
	bool has_fexit_sleep_fix;
	bool has_fentry_protection;
	bool has_bpf_cookie;
	bool has_kprobe_multi;

	struct mass_attacher_func_info *func_infos;
	int func_cnt;

	int func_info_cnts[MAX_FUNC_ARG_CNT + 1];
	int func_info_id_for_arg_cnt[MAX_FUNC_ARG_CNT + 1];

	struct kprobe_info *kprobes;
	int kprobe_cnt;

	int func_skip_cnt;

	int allow_glob_cnt;
	int deny_glob_cnt;
	struct {
		char *glob;
		int matches;
	} *allow_globs, *deny_globs;
};

struct mass_attacher *mass_attacher__new(struct SKEL_NAME *skel, struct mass_attacher_opts *opts)
{
	struct mass_attacher *att;
	int i, err;

	if (!skel)
		return NULL;

	att = calloc(1, sizeof(*att));
	if (!att)
		return NULL;

	att->skel = skel;

	if (!opts)
		return att;

	att->max_func_cnt = opts->max_func_cnt;
	att->max_fileno_rlimit = opts->max_fileno_rlimit;
	att->verbose = opts->verbose;
	att->debug = opts->debug;
	att->debug_extra = opts->debug_extra;
	if (att->debug)
		att->verbose = true;
	att->dry_run = opts->dry_run;
	att->use_fentries = !opts->use_kprobes;
	att->func_filter = opts->func_filter;

	for (i = 0; i < ARRAY_SIZE(enforced_deny_globs); i++) {
		err = mass_attacher__deny_glob(att, enforced_deny_globs[i]);
		if (err) {
			fprintf(stderr, "Failed to add enforced deny glob '%s': %d\n",
				enforced_deny_globs[i], err);
			mass_attacher__free(att);
			return NULL;
		}
	}

	return att;
}

void mass_attacher__free(struct mass_attacher *att)
{
	int i;

	if (!att)
		return;

	if (att->skel)
		att->skel->bss->ready = false;

	ksyms__free(att->ksyms);
	btf__free(att->vmlinux_btf);

	for (i = 0; i < att->func_cnt; i++) {
		struct mass_attacher_func_info *fi = &att->func_infos[i];

		bpf_link__destroy(fi->kentry_link);
		bpf_link__destroy(fi->kexit_link);
		if (fi->fentry_link_fd > 0)
			close(fi->fentry_link_fd);
		if (fi->fexit_link_fd > 0)
			close(fi->fexit_link_fd);
	}

	free(att->func_infos);

	if (att->kprobes) {
		for (i = 0; i < att->kprobe_cnt; i++)
			free(att->kprobes[i].name);
		free(att->kprobes);
	}

	for (i = 0; i <= MAX_FUNC_ARG_CNT; i++) {
		free(att->fentries_insns[i]);
		free(att->fexits_insns[i]);
	}

	SKEL_DESTROY(att->skel);

	free(att);
}

static bool is_valid_glob(const char *glob)
{
	int i, n;

	if (!glob) {
		fprintf(stderr, "NULL glob provided.\n");
		return false;
	}
	
	n = strlen(glob);
	if (n == 0) {
		fprintf(stderr, "Empty glob provided.\n");
		return false;
	}

	for (i = 0; i < n; i++) {
		if (glob[i] == '*' && i != 0 && i != n - 1) {
			fprintf(stderr,
				"Unsupported glob '%s': '*' allowed only at the beginning or end of a glob.\n",
				glob);
			return false;
		}
	}

	if (strcmp(glob, "**") == 0) {
		fprintf(stderr, "Unsupported glob '%s'.\n", glob);
		return false;
	}

	return true;
}

int mass_attacher__allow_glob(struct mass_attacher *att, const char *glob)
{
	void *tmp, *s;

	if (!is_valid_glob(glob))
		return -EINVAL;

	tmp = realloc(att->allow_globs, (att->allow_glob_cnt + 1) * sizeof(*att->allow_globs));
	if (!tmp)
		return -ENOMEM;
	att->allow_globs = tmp;

	s = strdup(glob);
	if (!s)
		return -ENOMEM;

	att->allow_globs[att->allow_glob_cnt].glob = s;
	att->allow_globs[att->allow_glob_cnt].matches = 0;
	att->allow_glob_cnt++;

	return 0;
}

int mass_attacher__deny_glob(struct mass_attacher *att, const char *glob)
{
	void *tmp, *s;

	if (!is_valid_glob(glob))
		return -EINVAL;

	tmp = realloc(att->deny_globs, (att->deny_glob_cnt + 1) * sizeof(*att->deny_globs));
	if (!tmp)
		return -ENOMEM;
	att->deny_globs = tmp;

	s = strdup(glob);
	if (!s)
		return -ENOMEM;

	att->deny_globs[att->deny_glob_cnt].glob = s;
	att->deny_globs[att->deny_glob_cnt].matches = 0;
	att->deny_glob_cnt++;


	return 0;
}

static int bump_rlimit(int resource, rlim_t max);
static int load_available_kprobes(struct mass_attacher *attacher);

static int func_arg_cnt(const struct btf *btf, int id);
static int find_kprobe(const struct mass_attacher *att, const char *name);
static bool is_func_type_ok(const struct btf *btf, const struct btf_type *t);
static int prepare_func(struct mass_attacher *att, const char *func_name,
			const struct btf_type *t, int btf_id);
static int calibrate_features(struct mass_attacher *att);

int mass_attacher__prepare(struct mass_attacher *att)
{
	int err, i, n;

	/* Load and cache /proc/kallsyms for IP <-> kfunc mapping */
	att->ksyms = ksyms__load();
	if (!att->ksyms) {
		fprintf(stderr, "Failed to load /proc/kallsyms\n");
		return -EINVAL;
	}

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	err = bump_rlimit(RLIMIT_MEMLOCK, RLIM_INFINITY);
	if (err) {
		fprintf(stderr, "Failed to set RLIM_MEMLOCK. Won't be able to load BPF programs: %d\n", err);
		return err;
	}

	/* Allow opening lots of BPF programs */
	err = bump_rlimit(RLIMIT_NOFILE, att->max_fileno_rlimit ?: 300000);
	if (err) {
		fprintf(stderr, "Failed to set RLIM_NOFILE. Won't be able to attach many BPF programs: %d\n", err);
		return err;
	}

	/* Detect supported features and calibrate kretprobe IP extraction */
	err = calibrate_features(att);
	if (err) {
		fprintf(stderr, "Failed to perform feature calibration: %d\n", err);
		return err;
	}

	if (att->use_fentries && !att->has_fexit_sleep_fix) {
		for (i = 0; i < ARRAY_SIZE(sleepable_deny_globs); i++) {
			err = mass_attacher__deny_glob(att, sleepable_deny_globs[i]);
			if (err) {
				fprintf(stderr, "Failed to add enforced deny glob '%s': %d\n",
					sleepable_deny_globs[i], err);
				return err;
			}
		}
	}

	att->skel->rodata->kret_ip_off = att->kret_ip_off;
	att->skel->rodata->has_fentry_protection = att->has_fentry_protection;
	att->skel->rodata->has_bpf_get_func_ip = att->has_bpf_get_func_ip;

	/* Load names of possible kprobes */
	err = load_available_kprobes(att);
	if (err) {
		fprintf(stderr, "Failed to read the list of available kprobes: %d\n", err);
		return err;
	}

	_Static_assert(MAX_FUNC_ARG_CNT == 6, "Unexpected maximum function arg count");
	att->fentries[0] = att->skel->progs.fentry0;
	att->fentries[1] = att->skel->progs.fentry1;
	att->fentries[2] = att->skel->progs.fentry2;
	att->fentries[3] = att->skel->progs.fentry3;
	att->fentries[4] = att->skel->progs.fentry4;
	att->fentries[5] = att->skel->progs.fentry5;
	att->fentries[6] = att->skel->progs.fentry6;
	att->fexits[0] = att->skel->progs.fexit0;
	att->fexits[1] = att->skel->progs.fexit1;
	att->fexits[2] = att->skel->progs.fexit2;
	att->fexits[3] = att->skel->progs.fexit3;
	att->fexits[4] = att->skel->progs.fexit4;
	att->fexits[5] = att->skel->progs.fexit5;
	att->fexits[6] = att->skel->progs.fexit6;

	att->vmlinux_btf = libbpf_find_kernel_btf();
	err = libbpf_get_error(att->vmlinux_btf);
	if (err) {
		fprintf(stderr, "Failed to load vmlinux BTF: %d\n", err);
		return -EINVAL;
	}

	n = btf__type_cnt(att->vmlinux_btf);
	for (i = 1; i < n; i++) {
		const struct btf_type *t = btf__type_by_id(att->vmlinux_btf, i);
		const char *func_name;

		if (!btf_is_func(t))
			continue;

		func_name = btf__str_by_offset(att->vmlinux_btf, t->name_off);

		err = prepare_func(att, func_name, t, i);
		if (err)
			return err;
	}
	if (!att->use_fentries) {
		for (i = 0; i < att->kprobe_cnt; i++) {
			if (att->kprobes[i].used)
				continue;

			err = prepare_func(att, att->kprobes[i].name, NULL, 0);
			if (err)
				return err;
		}
	}

	if (att->func_cnt == 0) {
		fprintf(stderr, "No matching functions found.\n");
		return -ENOENT;
	}

	if (att->use_fentries) {
		bpf_program__set_autoload(att->skel->progs.kentry, false);
		bpf_program__set_autoload(att->skel->progs.kexit, false);

		for (i = 0; i <= MAX_FUNC_ARG_CNT; i++) {
			struct mass_attacher_func_info *finfo;

			if (att->func_info_cnts[i]) {
				finfo = &att->func_infos[att->func_info_id_for_arg_cnt[i]];
				bpf_program__set_attach_target(att->fentries[i], 0, finfo->name);
				bpf_program__set_attach_target(att->fexits[i], 0, finfo->name);

				if (att->debug)
					printf("Found total %d functions with %d arguments.\n", att->func_info_cnts[i], i);
			} else {
				bpf_program__set_autoload(att->fentries[i], false);
				bpf_program__set_autoload(att->fexits[i], false);
			}
		}
	} else {
		for (i = 0; i <= MAX_FUNC_ARG_CNT; i++) {
			bpf_program__set_autoload(att->fentries[i], false);
			bpf_program__set_autoload(att->fexits[i], false);
		}
	}

	if (att->verbose) {
		printf("Found %d attachable functions in total.\n", att->func_cnt);
		printf("Skipped %d functions in total.\n", att->func_skip_cnt);

		if (att->debug) {
			for (i = 0; i < att->deny_glob_cnt; i++) {
				printf("Deny glob '%s' matched %d functions.\n",
				       att->deny_globs[i].glob, att->deny_globs[i].matches);
			}
			for (i = 0; i < att->allow_glob_cnt; i++) {
				printf("Allow glob '%s' matched %d functions.\n",
				       att->allow_globs[i].glob, att->allow_globs[i].matches);
			}
		}
	}

	bpf_map__set_max_entries(att->skel->maps.ip_to_id, att->func_cnt);

	return 0;
}

static int calibrate_features(struct mass_attacher *att)
{
	struct calib_feat_bpf *calib_skel;
	int err;

	calib_skel = calib_feat_bpf__open_and_load();
	if (!calib_skel) {
		fprintf(stderr, "Failed to load feature calibration skeleton\n");
		return -EFAULT;
	}

	calib_skel->bss->my_tid = syscall(SYS_gettid);

	err = calib_feat_bpf__attach(calib_skel);
	if (err) {
		fprintf(stderr, "Failed to attach feature calibration skeleton\n");
		calib_feat_bpf__destroy(calib_skel);
		return -EFAULT;
	}

	usleep(1);

	if (!calib_skel->bss->has_bpf_get_func_ip && calib_skel->bss->kret_ip_off == 0) {
		fprintf(stderr, "Failed to calibrate kretprobe func IP extraction.\n");
		return -EFAULT;
	}

	att->kret_ip_off = calib_skel->bss->kret_ip_off;
	att->has_bpf_get_func_ip = calib_skel->bss->has_bpf_get_func_ip;
	att->has_fexit_sleep_fix = calib_skel->bss->has_fexit_sleep_fix;
	att->has_fentry_protection = calib_skel->bss->has_fentry_protection;
	att->has_bpf_cookie = calib_skel->bss->has_bpf_cookie;
	att->has_kprobe_multi = calib_skel->bss->has_kprobe_multi;

	if (att->debug) {
		printf("Feature calibration results:\n"
		       "\tkretprobe IP offset: %d\n"
		       "\tfexit sleep fix: %s\n"
		       "\tfentry re-entry protection: %s\n",
		       att->kret_ip_off,
		       att->has_fexit_sleep_fix ? "yes" : "no",
		       att->has_fentry_protection ? "yes" : "no");
	}

	calib_feat_bpf__destroy(calib_skel);
	return 0;
}

static int prepare_func(struct mass_attacher *att, const char *func_name,
			const struct btf_type *t, int btf_id)
{
	const struct ksym *ksym;
	struct mass_attacher_func_info *finfo;
	int i, arg_cnt, kprobe_idx;
	void *tmp;

	ksym = ksyms__get_symbol(att->ksyms, func_name);
	if (!ksym) {
		if (att->verbose)
			printf("Function '%s' not found in /proc/kallsyms! Skipping.\n", func_name);
		att->func_skip_cnt++;
		return 0;
	}

	/* any deny glob forces skipping a function */
	for (i = 0; i < att->deny_glob_cnt; i++) {
		if (!glob_matches(att->deny_globs[i].glob, func_name))
			continue;

		att->deny_globs[i].matches++;

		if (att->debug_extra)
			printf("Function '%s' is denied by '%s' glob.\n",
			       func_name, att->deny_globs[i].glob);
		att->func_skip_cnt++;
		return 0;
	}

	/* if any allow glob is specified, function has to match one of them */
	if (att->allow_glob_cnt) {
		bool found = false;

		for (i = 0; i < att->allow_glob_cnt; i++) {
			if (!glob_matches(att->allow_globs[i].glob, func_name))
				continue;

			att->allow_globs[i].matches++;
			if (att->debug_extra)
				printf("Function '%s' is allowed by '%s' glob.\n",
				       func_name, att->allow_globs[i].glob);

			found = true;
			break;
		}

		if (!found) {
			if (att->debug_extra)
				printf("Function '%s' doesn't match any allow glob, skipping.\n", func_name);
			att->func_skip_cnt++;
			return 0;
		}
	}

	kprobe_idx = find_kprobe(att, func_name);
	if (kprobe_idx < 0) {
		if (att->debug_extra)
			printf("Function '%s' is not attachable kprobe, skipping.\n", func_name);
		att->func_skip_cnt++;
		return 0;
	}
	att->kprobes[kprobe_idx].used = true;

	if (att->use_fentries && !is_func_type_ok(att->vmlinux_btf, t)) {
		if (att->debug)
			printf("Function '%s' has prototype incompatible with fentry/fexit, skipping.\n", func_name);
		att->func_skip_cnt++;
		return 0;
	}

	if (att->func_filter && !att->func_filter(att, att->vmlinux_btf, i, func_name, att->func_cnt)) {
		if (att->debug)
			printf("Function '%s' skipped due to custom filter function.\n", func_name);
		att->func_skip_cnt++;
		return 0;
	}

	if (att->max_func_cnt && att->func_cnt >= att->max_func_cnt) {
		if (att->verbose)
			fprintf(stderr, "Maximum allowed number of functions (%d) reached, skipping the rest.\n",
			        att->max_func_cnt);
		return -E2BIG;
	}

	tmp = realloc(att->func_infos, (att->func_cnt + 1) * sizeof(*att->func_infos));
	if (!tmp)
		return -ENOMEM;
	att->func_infos = tmp;

	finfo = &att->func_infos[att->func_cnt];
	memset(finfo, 0, sizeof(*finfo));

	arg_cnt = func_arg_cnt(att->vmlinux_btf, btf_id);

	finfo->addr = ksym->addr;
	finfo->size = ksym->size;
	finfo->name = ksym->name;
	finfo->arg_cnt = arg_cnt;
	finfo->btf_id = btf_id;

	if (att->use_fentries) {
		att->func_info_cnts[arg_cnt]++;
		if (!att->func_info_id_for_arg_cnt[arg_cnt])
			att->func_info_id_for_arg_cnt[arg_cnt] = att->func_cnt;
	}

	att->func_cnt++;

	if (att->debug_extra)
		printf("Found function '%s' at address 0x%lx...\n", func_name, ksym->addr);

	return 0;
}

static int bump_rlimit(int resource, rlim_t max)
{
	struct rlimit rlim_new = {
		.rlim_cur	= max,
		.rlim_max	= max,
	};

	if (setrlimit(resource, &rlim_new))
		return -errno;

	return 0;
}

static int kprobe_order(const void *a, const void *b)
{
	const struct kprobe_info *k1 = a, *k2 = b;

	return strcmp(k1->name, k2->name);
}

static int kprobe_by_name(const void *a, const void *b)
{
	const char *name = a;
	const struct kprobe_info *k = b;

	return strcmp(name, k->name);
}

static int load_available_kprobes(struct mass_attacher *att)
{
	static char buf[512];
	static char buf2[512];
	const char *fname = "/sys/kernel/tracing/available_filter_functions";
	int cnt, err;
	void *tmp, *s;
	FILE *f;

	f = fopen(fname, "r");
	if (!f) {
		err = -errno;
		fprintf(stderr, "Failed to open %s: %d\n", fname, err);
		return err;
	}

	while ((cnt = fscanf(f, "%s%[^\n]\n", buf, buf2)) == 1) {
		tmp = realloc(att->kprobes, (att->kprobe_cnt + 1) * sizeof(*att->kprobes));
		if (!tmp)
			return -ENOMEM;
		att->kprobes = tmp;

		s = strdup(buf);
		att->kprobes[att->kprobe_cnt].name = s;
		att->kprobes[att->kprobe_cnt].used = false;
		att->kprobe_cnt++;

		if (!s)
			return -ENOMEM;
	}

	qsort(att->kprobes, att->kprobe_cnt, sizeof(*att->kprobes), kprobe_order);

	if (att->verbose)
		printf("Discovered %d available kprobes!\n", att->kprobe_cnt);

	return 0;
}

static int clone_prog(const struct bpf_program *prog, int attach_btf_id);

int mass_attacher__load(struct mass_attacher *att)
{
	int err = 0, i, map_fd;

	/* we can't pass extra context to hijack_progs, so we set thread-local
	 * cur_attacher variable temporarily for the duration of skeleton's
	 * load phase
	 */
	cur_attacher = att;
	/* Load & verify BPF programs */
	if (!att->dry_run)
		err = SKEL_LOAD(att->skel);
	cur_attacher = NULL;

	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		return err;
	}

	if (att->use_fentries && att->debug)
		printf("Preparing %d BPF program copies...\n", att->func_cnt * 2);

	if (att->dry_run)
		return 0;

	for (i = 0; i < att->func_cnt; i++) {
		struct mass_attacher_func_info *finfo = &att->func_infos[i];
		const char *func_name = att->func_infos[i].name;
		long func_addr = att->func_infos[i].addr;

		map_fd = bpf_map__fd(att->skel->maps.ip_to_id);
		err = bpf_map_update_elem(map_fd, &func_addr, &i, 0);
		if (err) {
			err = -errno;
			fprintf(stderr, "Failed to add 0x%lx -> '%s' lookup entry to BPF map: %d\n",
				func_addr, func_name, err);
			return err;
		}

		if (att->use_fentries) {
			err = clone_prog(att->fentries[finfo->arg_cnt], finfo->btf_id);
			if (err < 0) {
				fprintf(stderr, "Failed to clone FENTRY BPF program for function '%s': %d\n", func_name, err);
				return err;
			}
			finfo->fentry_prog_fd = err;

			err = clone_prog(att->fexits[finfo->arg_cnt], finfo->btf_id);
			if (err < 0) {
				fprintf(stderr, "Failed to clone FEXIT BPF program for function '%s': %d\n", func_name, err);
				return err;
			}
			finfo->fexit_prog_fd = err;
		}
	}
	return 0;
}

static int clone_prog(const struct bpf_program *prog, int attach_btf_id)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts,
		.expected_attach_type = bpf_program__get_expected_attach_type(prog),
		.attach_btf_id = attach_btf_id,
	);
	int fd;

	fd = bpf_prog_load(bpf_program__type(prog),
			   bpf_program__name(prog),
			   "Dual BSD/GPL",
			   bpf_program__insns(prog),
			   bpf_program__insn_cnt(prog),
			   &opts);
	if (fd < 0)
		return -errno;

	return fd;
}

int mass_attacher__attach(struct mass_attacher *att)
{
	int i, err;

	for (i = 0; i < att->func_cnt; i++) {
		struct mass_attacher_func_info *finfo = &att->func_infos[i];
		const char *func_name = finfo->name;
		long func_addr = finfo->addr;

		if (att->dry_run)
			goto skip_attach;

		if (att->use_fentries) {
			int prog_fd;

			prog_fd = att->func_infos[i].fentry_prog_fd;
			err = bpf_raw_tracepoint_open(NULL, prog_fd);
			if (err < 0) {
				fprintf(stderr, "Failed to attach FENTRY prog (fd %d) for func #%d (%s) at addr %lx: %d\n",
					prog_fd, i + 1, func_name, func_addr, -errno);
				return err;
			}
			att->func_infos[i].fentry_link_fd = err;

			prog_fd = att->func_infos[i].fexit_prog_fd;
			err = bpf_raw_tracepoint_open(NULL, prog_fd);
			if (err < 0) {
				fprintf(stderr, "Failed to attach FEXIT prog (fd %d) for func #%d (%s) at addr %lx: %d\n",
					prog_fd, i + 1, func_name, func_addr, -errno);
				return err;
			}
			att->func_infos[i].fexit_link_fd = err;
		} else {
			finfo->kentry_link = bpf_program__attach_kprobe(att->skel->progs.kentry, false, func_name);
			err = libbpf_get_error(finfo->kentry_link);
			if (err) {
				fprintf(stderr, "Failed to attach KPROBE prog for func #%d (%s) at addr %lx: %d\n",
					i + 1, func_name, func_addr, err);
				return err;
			}

			finfo->kexit_link = bpf_program__attach_kprobe(att->skel->progs.kexit, true, func_name);
			err = libbpf_get_error(finfo->kexit_link);
			if (err) {
				fprintf(stderr, "Failed to attach KRETPROBE prog for func #%d (%s) at addr %lx: %d\n",
					i + 1, func_name, func_addr, err);
				return err;
			}
		}

skip_attach:
		if (att->debug) {
			printf("Attached%s to function #%d '%s' (addr %lx, btf id %d).\n",
			       att->dry_run ? " (dry run)" : "", i + 1,
			       func_name, func_addr, finfo->btf_id);
		} else if (att->verbose) {
			printf("Attached%s to function #%d '%s'.\n",
			att->dry_run ? " (dry run)" : "", i + 1, func_name);
		}
	}

	if (att->verbose) {
		printf("Total %d kernel functions attached%s successfully!\n",
			att->func_cnt, att->dry_run ? " (dry run)" : "");
	}

	return 0;
}

void mass_attacher__activate(struct mass_attacher *att)
{
	att->skel->bss->ready = true;
}

struct SKEL_NAME *mass_attacher__skeleton(const struct mass_attacher *att)
{
	return att->skel;
}

const struct btf *mass_attacher__btf(const struct mass_attacher *att)
{
	return att->vmlinux_btf;
}

size_t mass_attacher__func_cnt(const struct mass_attacher *att)
{
	return att->func_cnt;
}

const struct mass_attacher_func_info *mass_attacher__func(const struct mass_attacher *att, int id)
{
	if (id < 0 || id >= att->func_cnt)
		return NULL;
	return &att->func_infos[id];
}

static int find_kprobe(const struct mass_attacher *att, const char *name)
{
	struct kprobe_info *k;

	k = bsearch(name, att->kprobes, att->kprobe_cnt, sizeof(*att->kprobes), kprobe_by_name);

	return k == NULL ? -1 : k - att->kprobes;
}

static int func_arg_cnt(const struct btf *btf, int id)
{
	const struct btf_type *t;

	/* no BTF type info is available */
	if (id == 0)
		return 0;

	t = btf__type_by_id(btf, id);
	t = btf__type_by_id(btf, t->type);
	return btf_vlen(t);
}

static bool is_arg_type_ok(const struct btf *btf, const struct btf_type *t)
{
	while (btf_is_mod(t) || btf_is_typedef(t))
		t = btf__type_by_id(btf, t->type);
	if (!btf_is_int(t) && !btf_is_ptr(t) && !btf_is_enum(t))
		return false;
	return true;
}

static bool is_ret_type_ok(const struct btf *btf, const struct btf_type *t)
{
	while (btf_is_mod(t) || btf_is_typedef(t))
		t = btf__type_by_id(btf, t->type);

	if (btf_is_int(t) || btf_is_enum(t))
		return true;

	/* non-pointer types are rejected */
	if (!btf_is_ptr(t))
		return false;

	/* pointer to void is fine */
	if (t->type == 0) 
		return true;

	/* only pointer to struct/union is allowed */
	t = btf__type_by_id(btf, t->type);
	if (!btf_is_composite(t))
		return false;

	return true;
}

static bool is_func_type_ok(const struct btf *btf, const struct btf_type *t)
{
	const struct btf_param *p;
	int i;

	t = btf__type_by_id(btf, t->type);
	if (btf_vlen(t) > MAX_FUNC_ARG_CNT)
		return false;

	/* IGNORE VOID FUNCTIONS, THIS SHOULDN'T BE DONE IN GENERAL!!! */
	if (!t->type)
		return false;

	if (t->type && !is_ret_type_ok(btf, btf__type_by_id(btf, t->type)))
		return false;

	for (i = 0; i < btf_vlen(t); i++) {
		p = btf_params(t) + i;

		/* vararg not supported */
		if (!p->type)
			return false;

		if (!is_arg_type_ok(btf, btf__type_by_id(btf, p->type)))
			return false;
	}

	return true;
}

bool glob_matches(const char *glob, const char *s)
{
	int n = strlen(glob);

	if (n == 1 && glob[0] == '*')
		return true;

	if (glob[0] == '*' && glob[n - 1] == '*') {
		const char *subs;
		/* substring match */

		/* this is hacky, but we don't want to allocate for no good reason */
		((char *)glob)[n - 1] = '\0';
		subs = strstr(s, glob + 1);
		((char *)glob)[n - 1] = '*';

		return subs != NULL;
	} else if (glob[0] == '*') {
		size_t nn = strlen(s);
		/* suffix match */

		/* too short for a given suffix */
		if (nn < n - 1)
			return false;

		return strcmp(s + nn - (n - 1), glob + 1) == 0;
	} else if (glob[n - 1] == '*') {
		/* prefix match */
		return strncmp(s, glob, n - 1) == 0;
	} else {
		/* exact match */
		return strcmp(glob, s) == 0;
	}
}

