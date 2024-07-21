// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2021 Facebook */
#include <argp.h>
#include <ctype.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/btf.h>
#include <linux/perf_event.h>
#include <sys/utsname.h>
#include <sys/syscall.h>
#include <time.h>
#include "retsnoop.h"
#include "retsnoop.skel.h"
#include "calib_feat.skel.h"
#include "env.h"
#include "logic.h"
#include "ksyms.h"
#include "addr2line.h"
#include "mass_attacher.h"
#include "utils.h"

static int process_cu_globs()
{
	int err = 0;
	int i;

	for (i = 0; i < env.cu_allow_glob_cnt; i++) {
		err = append_compile_unit(env.ctx.a2l, &env.allow_globs, &env.allow_glob_cnt,
					  env.cu_allow_globs[i], false /*mandatory*/);
		if (err < 0)
			return err;
	}

	for (i = 0; i < env.cu_deny_glob_cnt; i++) {
		err = append_compile_unit(env.ctx.a2l, &env.deny_globs, &env.deny_glob_cnt,
					  env.cu_deny_globs[i], false /*mandatory*/);
		if (err < 0)
			return err;
	}

	for (i = 0; i < env.cu_entry_glob_cnt; i++) {
		err = append_compile_unit(env.ctx.a2l, &env.entry_globs, &env.entry_glob_cnt,
					  env.cu_entry_globs[i], false /*mandatory*/);
		if (err < 0)
			return err;
	}

	return err;
}

static int find_vmlinux(char *path, size_t max_len, bool soft)
{
	const char *locations[] = {
		"/boot/vmlinux-%1$s",
		"/lib/modules/%1$s/vmlinux-%1$s",
		"/lib/modules/%1$s/build/vmlinux",
		"/usr/lib/modules/%1$s/kernel/vmlinux",
		"/usr/lib/debug/boot/vmlinux-%1$s",
		"/usr/lib/debug/boot/vmlinux-%1$s.debug",
		"/usr/lib/debug/lib/modules/%1$s/vmlinux",
	};
	struct utsname buf;
	int i;

	uname(&buf);

	for (i = 0; i < ARRAY_SIZE(locations); i++) {
		snprintf(path, PATH_MAX, locations[i], buf.release);

		if (access(path, R_OK)) {
			if (env.debug)
				printf("No vmlinux image at %s found...\n", path);
			continue;
		}

		if (env.verbose)
			printf("Using vmlinux image at %s.\n", path);

		return 0;
	}

	if (!soft || env.verbose)
		fprintf(soft ? stdout : stderr, "Failed to locate vmlinux image location. Please use -k <vmlinux-path> to specify explicitly.\n");

	path[0] = '\0';

	return -ESRCH;
}

static int detect_kernel_features(void)
{
	struct calib_feat_bpf *skel;
	int err;

	skel = calib_feat_bpf__open_and_load();
	if (!skel) {
		err = -errno;
		fprintf(stderr, "Failed to load feature detection skeleton.\n");
		return err;
	}

	if (!skel->bss) {
		fprintf(stderr, "Kernel doesn't support memory mapping BPF global vars, you might need newer Linux kernel.\n");
		err = -EOPNOTSUPP;
		goto out;
	}

	skel->bss->my_tid = syscall(SYS_gettid);

	err = calib_feat_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach feature detection skeleton.\n");
		goto out;
	}

	/* trigger ksyscall and kretsyscall probes */
	syscall(__NR_nanosleep, NULL, NULL);

	if (!skel->bss->calib_entry_happened || !skel->bss->calib_exit_happened) {
		fprintf(stderr, "Calibration failure, BPF probes weren't triggered!\n");
		goto out;
	}

	if (env.debug) {
		printf("Feature detection:\n"
		       "\tBPF ringbuf map supported: %s\n"
		       "\tbpf_get_func_ip() supported: %s\n"
		       "\tbpf_get_branch_snapshot() supported: %s\n"
		       "\tBPF cookie supported: %s\n"
		       "\tmulti-attach kprobe supported: %s\n",
		       skel->bss->has_ringbuf ? "yes" : "no",
		       skel->bss->has_bpf_get_func_ip ? "yes" : "no",
		       skel->bss->has_branch_snapshot ? "yes" : "no",
		       skel->bss->has_bpf_cookie ? "yes" : "no",
		       skel->bss->has_kprobe_multi ? "yes" : "no");
		printf("Feature calibration:\n"
		       "\tkretprobe IP offset: %d\n"
		       "\tfexit sleep fix: %s\n"
		       "\tfentry re-entry protection: %s\n",
		       skel->bss->kret_ip_off,
		       skel->bss->has_fexit_sleep_fix ? "yes" : "no",
		       skel->bss->has_fentry_protection ? "yes" : "no");
	}

	env.has_ringbuf = skel->bss->has_ringbuf;
	env.has_branch_snapshot = skel->bss->has_branch_snapshot;

out:
	calib_feat_bpf__destroy(skel);
	return err;
}

static int create_lbr_perf_events(int *fds, int cpu_cnt)
{
	struct perf_event_attr attr;
	int cpu, err;

	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.type = PERF_TYPE_HARDWARE;
	attr.config = PERF_COUNT_HW_CPU_CYCLES;
	attr.sample_type = PERF_SAMPLE_BRANCH_STACK;
	attr.branch_sample_type = PERF_SAMPLE_BRANCH_KERNEL |
				  (env.lbr_flags ?: PERF_SAMPLE_BRANCH_ANY_RETURN);

	if (env.debug)
		printf("LBR flags are 0x%lx\n", (long)attr.branch_sample_type);

	for (cpu = 0; cpu < env.cpu_cnt; cpu++) {
		fds[cpu] = syscall(__NR_perf_event_open, &attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
		if (fds[cpu] < 0) {
			err = -errno;
			for (cpu--; cpu >= 0; cpu--) {
				close(fds[cpu]);
				fds[cpu] = -1;
			}
			return err;
		}
	}

	return 0;
}

static inline bool is_pow_of_2(long x)
{
	return x && (x & (x - 1)) == 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.debug_extra)
		return 0;
	return vfprintf(stderr, format, args);
}

static int libbpf_noop_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return 0;
}

static volatile sig_atomic_t exiting;

static void sig_handler(int sig)
{
	exiting = true;

	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
}

const struct func_info *func_info(const struct ctx *ctx, __u32 id)
{
	return &ctx->skel->data_func_infos->func_infos[id];
}

long read_dropped_sessions(void)
{
	return atomic_load(&env.ctx.skel->bss->stats.dropped_sessions);
}

int main(int argc, char **argv, char **envp)
{
	struct mass_attacher_opts att_opts = {};
	struct ksyms *ksyms = NULL;
	struct mass_attacher *att = NULL;
	struct retsnoop_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	int *lbr_perf_fds = NULL;
	char vmlinux_path[1024] = {};
	const struct ksym *stext_sym = 0;
	int err, i, j, n;
	size_t tmp_n;
	uint64_t ts1, ts2;

	if (setvbuf(stdout, NULL, _IOLBF, BUFSIZ))
		fprintf(stderr, "Failed to set output mode to line-buffered!\n");

	/* Parse command line arguments */
	setenv("ARGP_HELP_FMT", "rmargin=99", 0 /* !overwrite */);
	err = argp_parse(&argp, argc, argv, ARGP_NO_HELP, NULL, NULL);
	if (err)
		return -1;

	if (env.show_version) {
		printf("%s\n", argp_program_version);
		if (env.verbose) {
			libbpf_set_print(libbpf_noop_print_fn);
			env.debug = true;
			if (detect_kernel_features()) {
				printf("Failed to do feature detection, please run retsnoop as root!\n");
				return 1;
			}
		}
		return 0;
	}

	if (env.show_config_help) {
		print_config_help_message();
		return 0;
	}

	if (geteuid() != 0)
		fprintf(stderr, "You are not running as root! Expect failures. Please use sudo or run as root.\n");

	/* Load and cache /proc/kallsyms for IP <-> kfunc mapping */
	env.ctx.ksyms = ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "Failed to load /proc/kallsyms\n");
		err = -EINVAL;
		goto cleanup_silent;
	}

	stext_sym = ksyms__get_symbol(ksyms, "_stext", NULL, KSYM_FUNC);
	if (!stext_sym) {
		fprintf(stderr, "Failed to determine _stext address from /proc/kallsyms\n");
		err = -EINVAL;
		goto cleanup_silent;
	}

	if (env.symb_mode == SYMB_DEFAULT && !env.vmlinux_path) {
		if (find_vmlinux(vmlinux_path, sizeof(vmlinux_path), true /* soft */))
			env.symb_mode = SYMB_NONE;
	}

	if (env.symb_mode != SYMB_NONE || env.cu_allow_glob_cnt || env.cu_deny_glob_cnt || env.cu_entry_glob_cnt) {
		bool symb_inlines = false;;

		if (!env.vmlinux_path &&
		    vmlinux_path[0] == '\0' &&
		    find_vmlinux(vmlinux_path, sizeof(vmlinux_path), false /* hard error */)) {
			err = -EINVAL;
			goto cleanup_silent;
		}

		if (env.symb_mode == SYMB_DEFAULT || (env.symb_mode & SYMB_INLINES))
			symb_inlines = true;

		env.ctx.a2l = addr2line__init(env.vmlinux_path ?: vmlinux_path, stext_sym->addr,
					      env.verbose, symb_inlines, envp);
		if (!env.ctx.a2l) {
			fprintf(stderr, "Failed to start addr2line for vmlinux image at %s!\n",
				env.vmlinux_path ?: vmlinux_path);
			err = -EINVAL;
			goto cleanup_silent;
		}
	}

	if (process_cu_globs()) {
		fprintf(stderr, "Failed to process file paths.\n");
		err = -EINVAL;
		goto cleanup_silent;
	}

	if (env.entry_glob_cnt == 0) {
		fprintf(stderr, "No entry point globs specified. "
				"Please provide entry glob(s) ('-e GLOB') and/or any preset ('-c PRESET').\n");
		err = -EINVAL;
		goto cleanup_silent;
	}

	/* determine mapping from bpf_ktime_get_ns() to real clock */
	calibrate_ktime();

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	if (detect_kernel_features()) {
		fprintf(stderr, "Kernel feature detection failed.\n");
		err = -1;
		goto cleanup_silent;
	}

	env.cpu_cnt = libbpf_num_possible_cpus();
	if (env.cpu_cnt <= 0) {
		fprintf(stderr, "Failed to determine number of CPUs: %d\n", env.cpu_cnt);
		err = -EINVAL;
		goto cleanup_silent;
	}

	if (!env.has_ringbuf) {
		fprintf(stderr, "Retsnoop requires BPF ringbuf (Linux 5.8+), please upgrade your kernel!\n");
		err = -EOPNOTSUPP;
		goto cleanup_silent;
	}
#ifndef __x86_64__
	if (env.capture_args) {
		elog("Function arguments capture is only supported on x86-64 architecture!\n");
		err = -EOPNOTSUPP;
		goto cleanup_silent;
	}
#endif

	/* Open BPF skeleton */
	env.ctx.skel = skel = retsnoop_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton.\n");
		err = -EINVAL;
		goto cleanup_silent;
	}

	bpf_map__set_max_entries(skel->maps.rb, env.ringbuf_map_sz);
	bpf_map__set_max_entries(skel->maps.sessions, env.sessions_map_sz);

	skel->rodata->tgid_allow_cnt = env.allow_pid_cnt;
	skel->rodata->tgid_deny_cnt = env.deny_pid_cnt;
	if (env.allow_pid_cnt + env.deny_pid_cnt > 0) {
		bpf_map__set_max_entries(skel->maps.tgids_filter,
					 env.allow_pid_cnt + env.deny_pid_cnt);
	}

	skel->rodata->comm_allow_cnt = env.allow_comm_cnt;
	skel->rodata->comm_deny_cnt = env.deny_comm_cnt;
	if (env.allow_comm_cnt + env.deny_comm_cnt > 0) {
		bpf_map__set_max_entries(skel->maps.comms_filter,
					 env.allow_comm_cnt + env.deny_comm_cnt);
	}

	/* turn on extra bpf_printk()'s on BPF side */
	skel->rodata->verbose = env.debug_feats & DEBUG_BPF;
	skel->rodata->extra_verbose = (env.debug_feats & DEBUG_BPF) && env.debug_extra;
	skel->rodata->targ_tgid = env.pid;
	skel->rodata->emit_success_stacks = env.emit_success_stacks;
	skel->rodata->duration_ns = env.longer_than_ms * 1000000ULL;

	memset(skel->rodata->spaces, ' ', sizeof(skel->rodata->spaces) - 1);

	/* LBR detection and setup */
	if (env.use_lbr && env.has_branch_snapshot) {
		lbr_perf_fds = malloc(sizeof(int) * env.cpu_cnt);
		if (!lbr_perf_fds) {
			err = -ENOMEM;
			goto cleanup_silent;
		}
		for (i = 0; i < env.cpu_cnt; i++) {
			lbr_perf_fds[i] = -1;
		}

		err = create_lbr_perf_events(lbr_perf_fds, env.cpu_cnt);
		if (err) {
			if (env.verbose)
				fprintf(stderr, "Failed to create LBR perf events: %d. Disabling LBR capture.\n", err);
			err = 0;
		} else {
			env.has_lbr = true;
		}
	}
	env.use_lbr = env.use_lbr && env.has_lbr && env.has_branch_snapshot;
	skel->rodata->use_lbr = env.use_lbr;
	if (env.use_lbr && env.verbose)
		printf("LBR capture enabled.\n");

	skel->rodata->emit_func_trace = env.emit_func_trace;

	skel->rodata->capture_args = env.capture_args;
	skel->rodata->use_kprobes = env.attach_mode != ATTACH_FENTRY;

	att_opts.verbose = env.verbose;
	att_opts.debug = env.debug;
	att_opts.debug_extra = env.debug_extra;
	att_opts.debug_multi_kprobe = env.debug_feats & DEBUG_MULTI_KPROBE;
	att_opts.dry_run = env.dry_run;
	switch (env.attach_mode) {
	case ATTACH_DEFAULT:
	case ATTACH_KPROBE_MULTI:
		att_opts.attach_mode = MASS_ATTACH_KPROBE;
		break;
	case ATTACH_KPROBE_SINGLE:
		att_opts.attach_mode = MASS_ATTACH_KPROBE_SINGLE;
		break;
	case ATTACH_FENTRY:
		att_opts.attach_mode = MASS_ATTACH_FENTRY;
		break;
	default:
		fprintf(stderr, "Unrecognized attach mode: %d.\n", env.attach_mode);
		err = -EINVAL;
		goto cleanup_silent;
	}
	att = mass_attacher__new(skel, ksyms, &att_opts);
	if (!att)
		goto cleanup_silent;

	/* entry globs are allow globs as well */
	for (i = 0; i < env.entry_glob_cnt; i++) {
		struct glob *g = &env.entry_globs[i];

		err = mass_attacher__allow_glob(att, g->name, g->mod);
		if (err)
			goto cleanup_silent;
	}
	for (i = 0; i < env.allow_glob_cnt; i++) {
		struct glob *g = &env.allow_globs[i];

		err = mass_attacher__allow_glob(att, g->name, g->mod);
		if (err)
			goto cleanup_silent;
	}
	for (i = 0; i < env.deny_glob_cnt; i++) {
		struct glob *g = &env.deny_globs[i];

		err = mass_attacher__deny_glob(att, g->name, g->mod);
		if (err)
			goto cleanup_silent;
	}

	err = mass_attacher__prepare(att);
	if (err)
		goto cleanup_silent;

	n = mass_attacher__func_cnt(att);
	/* Set up dynamically sized array of func_infos. On BPF side we need
	 * it to be a power-of-2 sized.
	 */
	if (is_pow_of_2(n)) {
		tmp_n = n;
	} else {
		for (tmp_n = 1; tmp_n <= INT_MAX / 4; tmp_n *= 2) {
			if (tmp_n >= n)
				break;
		}
		if (tmp_n >= INT_MAX / 2) {
			err = -E2BIG;
			fprintf(stderr, "Unrealistically large number of functions: %zu!\n", tmp_n);
			goto cleanup_silent;
		}
	}
	skel->rodata->func_info_mask = tmp_n - 1;
	err = bpf_map__set_value_size(skel->maps.data_func_infos, tmp_n * sizeof(struct func_info));
	if (err) {
		fprintf(stderr, "Failed to dynamically size func info table: %d\n", err);
		goto cleanup_silent;
	}
	skel->data_func_infos = bpf_map__initial_value(skel->maps.data_func_infos, &tmp_n);

	if (env.capture_args) {
		for (i = 0; i < n; i++) {
			const struct mass_attacher_func_info *finfo;

			finfo = mass_attacher__func(att, i);
			err = prepare_fn_args_specs(i, finfo);
			if (err) {
				elog("Failed to preprocess function argument specs: %d\n", err);
				goto cleanup_silent;
			}
		}
	}

	for (i = 0; i < n; i++) {
		const struct mass_attacher_func_info *finfo;
		const struct glob *glob;
		struct func_info *fi;
		enum func_flags flags;

		finfo = mass_attacher__func(att, i);
		flags = func_flags(finfo->name, finfo->btf, finfo->btf_id);

		for (j = 0; j < env.entry_glob_cnt; j++) {
			glob = &env.entry_globs[j];
			if (!full_glob_matches(glob->name, glob->mod, finfo->name, finfo->module))
				continue;

			flags |= FUNC_IS_ENTRY;

			if (env.verbose) {
				printf("Function '%s%s%s%s' is marked as an entry point.\n",
				       NAME_MOD(finfo->name, finfo->module));
			}

			break;
		}

		fi = (struct func_info *)func_info(&env.ctx, i);
		strncpy(fi->name, finfo->name, MAX_FUNC_NAME_LEN - 1);
		fi->name[MAX_FUNC_NAME_LEN - 1] = '\0';
		fi->ip = finfo->addr;
		fi->flags = flags;

		if (env.capture_args) {
			const struct func_args_info *fn_args = func_args_info(i);

			for (j = 0; j < fn_args->arg_spec_cnt; j++) {
				fi->arg_specs[j] = fn_args->arg_specs[j].arg_flags;
			}
		}
	}

	for (i = 0; i < env.entry_glob_cnt; i++) {
		const struct glob *glob = &env.entry_globs[i];
		bool matched = false;

		for (j = 0; j < n; j++) {
			const struct mass_attacher_func_info *finfo = mass_attacher__func(att, j);

			if (full_glob_matches(glob->name, glob->mod, finfo->name, finfo->module)) {
				matched = true;
				break;
			}
		}

		if (!matched && glob->mandatory) {
			err = -ENOENT;
			fprintf(stderr, "Entry glob '%s%s%s%s' doesn't match any kernel function!\n",
				NAME_MOD(glob->name, glob->mod));
			goto cleanup_silent;
		}
	}

	err = mass_attacher__load(att);
	if (err)
		goto cleanup;

	for (i = 0; i < env.allow_pid_cnt; i++) {
		int tgid = env.allow_pids[i];
		bool verdict = true; /* allowed */

		err = bpf_map_update_elem(bpf_map__fd(skel->maps.tgids_filter),
					  &tgid, &verdict, BPF_ANY);
		if (err) {
			err = -errno;
			fprintf(stderr, "Failed to setup PID allowlist: %d\n", err);
			goto cleanup;
		}
	}
	/* denylist overrides allowlist, if overlaps */
	for (i = 0; i < env.deny_pid_cnt; i++) {
		int tgid = env.deny_pids[i];
		bool verdict = false; /* denied */

		err = bpf_map_update_elem(bpf_map__fd(skel->maps.tgids_filter),
					  &tgid, &verdict, BPF_ANY);
		if (err) {
			err = -errno;
			fprintf(stderr, "Failed to setup PID denylist: %d\n", err);
			goto cleanup;
		}
	}
	for (i = 0; i < env.allow_comm_cnt; i++) {
		const char *comm = env.allow_comms[i];
		char buf[TASK_COMM_LEN] = {};
		bool verdict = true; /* allowed */

		strncat(buf, comm, TASK_COMM_LEN - 1);

		err = bpf_map_update_elem(bpf_map__fd(skel->maps.comms_filter),
					  &buf, &verdict, BPF_ANY);
		if (err) {
			err = -errno;
			fprintf(stderr, "Failed to setup COMM allowlist: %d\n", err);
			goto cleanup;
		}
	}
	/* denylist overrides allowlist, if overlaps */
	for (i = 0; i < env.deny_comm_cnt; i++) {
		const char *comm = env.deny_comms[i];
		char buf[TASK_COMM_LEN] = {};
		bool verdict = false; /* denied */

		strncat(buf, comm, TASK_COMM_LEN - 1);

		err = bpf_map_update_elem(bpf_map__fd(skel->maps.comms_filter),
					  &buf, &verdict, BPF_ANY);
		if (err) {
			err = -errno;
			fprintf(stderr, "Failed to setup COMM denylist: %d\n", err);
			goto cleanup;
		}
	}

	ts1 = now_ns();
	err = mass_attacher__attach(att);
	if (err)
		goto cleanup;
	ts2 = now_ns();
	if (env.verbose)
		printf("Successfully attached in %ld ms.\n", (long)((ts2 - ts1) / 1000000));

	if (env.dry_run) {
		if (env.verbose)
			printf("Dry run successful, exiting...\n");
		goto cleanup_silent;
	}

	signal(SIGTERM, sig_handler);
	signal(SIGINT, sig_handler);

	env.ctx.att = att;
	env.ctx.ksyms = ksyms__load();
	if (!env.ctx.ksyms) {
		fprintf(stderr, "Failed to load /proc/kallsyms for symbolization.\n");
		goto cleanup;
	}

	/* Set up ring/perf buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &env.ctx, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Allow mass tracing */
	mass_attacher__activate(att);

	/* Process events */
	if (env.debug_feats & DEBUG_BPF)
		printf("BPF-side logging is enabled. Use `sudo cat /sys/kernel/tracing/trace_pipe` to see logs.\n");
	printf("Receiving data...\n");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			goto cleanup;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			goto cleanup;
		}
	}

cleanup:
	printf("\nDetaching...\n");

	if (env.ctx.skel && env.ctx.skel->bss) {
		long dropped_sessions = read_dropped_sessions();
		long incomplete_sessions = atomic_load(&env.ctx.skel->bss->stats.incomplete_sessions);

		if (dropped_sessions || incomplete_sessions) {
			fprintf(stderr, "WARNING! There were dropped or incomplete data. Output might be incomplete!\n");
			fprintf(stderr, "%-20s %ld\n", "DROPPED SAMPLES:", dropped_sessions);
			fprintf(stderr, "%-20s %ld\n", "INCOMPLETE SAMPLES:", incomplete_sessions);
		}
	}

cleanup_silent:
	fflush(stdout);

	ts1 = now_ns();

	mass_attacher__free(att);

	addr2line__free(env.ctx.a2l);
	ksyms__free(env.ctx.ksyms);

	for (i = 0; i < env.cpu_cnt; i++) {
		if (lbr_perf_fds && lbr_perf_fds[i] >= 0)
			close(lbr_perf_fds[i]);
	}
	free(lbr_perf_fds);

	for (i = 0; i < env.allow_glob_cnt; i++) {
		free(env.allow_globs[i].name);
		free(env.allow_globs[i].mod);
	}
	free(env.allow_globs);
	for (i = 0; i < env.deny_glob_cnt; i++) {
		free(env.deny_globs[i].name);
		free(env.deny_globs[i].mod);
	}
	free(env.deny_globs);
	for (i = 0; i < env.entry_glob_cnt; i++) {
		free(env.entry_globs[i].name);
		free(env.entry_globs[i].mod);
	}
	free(env.entry_globs);

	for (i = 0; i < env.allow_comm_cnt; i++)
		free(env.allow_comms[i]);
	free(env.allow_comms);
	for (i = 0; i < env.deny_comm_cnt; i++)
		free(env.deny_comms[i]);
	free(env.deny_comms);

	free(env.allow_pids);
	free(env.deny_pids);

	if (err == 0) {
		ts2 = now_ns();
		printf("DONE in %ld ms.\n", (long)((ts2 - ts1) / 1000000));
	}

	return -err;
}
