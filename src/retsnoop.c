// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2021 Facebook */
#include <argp.h>
#include <ctype.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
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
#include "ksyms.h"
#include "addr2line.h"
#include "mass_attacher.h"
#include "utils.h"
#include "hashmap.h"

struct ctx {
	struct mass_attacher *att;
	struct retsnoop_bpf *skel;
	struct ksyms *ksyms;
	struct addr2line *a2l;
};

enum attach_mode {
	ATTACH_DEFAULT,
	ATTACH_KPROBE_MULTI,
	ATTACH_KPROBE_SINGLE,
	ATTACH_FENTRY,
};

enum symb_mode {
	SYMB_NONE = -1,

	SYMB_DEFAULT = 0,
	SYMB_LINEINFO = 0x1,
	SYMB_INLINES = 0x2,
};

enum debug_feat {
	DEBUG_NONE = 0x00,
	DEBUG_MULTI_KPROBE = 0x01,
};

static struct env {
	bool show_version;
	bool verbose;
	bool debug;
	bool debug_extra;
	bool bpf_logs;
	bool dry_run;
	bool emit_success_stacks;
	bool emit_full_stacks;
	bool emit_intermediate_stacks;
	bool emit_func_trace;
	enum attach_mode attach_mode;
	enum symb_mode symb_mode;
	enum debug_feat debug_feats;
	bool use_lbr;
	long lbr_flags;
	int lbr_max_cnt;
	const char *vmlinux_path;
	int pid;
	int longer_than_ms;

	struct glob *allow_globs;
	struct glob *deny_globs;
	struct glob *entry_globs;
	int allow_glob_cnt;
	int deny_glob_cnt;
	int entry_glob_cnt;

	char **cu_allow_globs;
	char **cu_deny_globs;
	char **cu_entry_globs;
	int cu_allow_glob_cnt;
	int cu_deny_glob_cnt;
	int cu_entry_glob_cnt;

	int *allow_pids;
	int *deny_pids;
	int allow_pid_cnt;
	int deny_pid_cnt;

	char **allow_comms;
	char **deny_comms;
	int allow_comm_cnt;
	int deny_comm_cnt;

	int allow_error_cnt;
	bool has_error_filter;
	__u64 allow_error_mask[MAX_ERR_CNT / 64];
	__u64 deny_error_mask[MAX_ERR_CNT / 64];

	struct ctx ctx;
	int ringbuf_sz;
	int perfbuf_percpu_sz;
	int stacks_map_sz;

	int cpu_cnt;
	bool has_branch_snapshot;
	bool has_lbr;
	bool has_ringbuf;
} env = {
	.ringbuf_sz = 8 * 1024 * 1024,
	.perfbuf_percpu_sz = 256 * 1024,
	.stacks_map_sz = 4096,
};

const char *argp_program_version = "retsnoop v0.9.7";
const char *argp_program_bug_address = "Andrii Nakryiko <andrii@kernel.org>";
const char argp_program_doc[] =
"retsnoop tool shows kernel call stacks based on specified function filters.\n"
"\n"
"USAGE: retsnoop [-v] [-F|-K|-M] [-T] [--lbr] [-c CASE]* [-a GLOB]* [-d GLOB]* [-e GLOB]*\n";

#define OPT_FULL_STACKS 1001
#define OPT_STACKS_MAP_SIZE 1002
#define OPT_LBR_MAX_CNT 1003
#define OPT_DRY_RUN 1004
#define OPT_DEBUG_FEAT 1005

static const struct argp_option opts[] = {
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{ "verbose", 'v', "LEVEL", OPTION_ARG_OPTIONAL,
	  "Verbose output (use -vv for debug-level verbosity, -vvv for libbpf debug log)" },
	{ "version", 'V', NULL, 0,
	  "Print out retsnoop version." },
	{ "bpf-logs", 'l', NULL, 0,
	  "Emit BPF-side logs (use `sudo cat /sys/kernel/debug/tracing/trace_pipe` to read)" },
	{ "dry-run", OPT_DRY_RUN, NULL, 0,
	  "Perform a dry run (don't actually load and attach BPF programs)" },

	/* Attach mechanism specification */
	{ "kprobes-multi", 'M', NULL, 0,
	  "Use multi-attach kprobes/kretprobes, if supported; fall back to single-attach kprobes/kretprobes, otherwise" },
	{ "kprobes", 'K', NULL, 0,
	  "Use single-attach kprobes/kretprobes" },
	{ "fentries", 'F', NULL, 0,
	  "Use fentries/fexits instead of kprobes/kretprobes" },

	/* Target functions specification */
	{ "case", 'c', "CASE", 0,
	  "Use a pre-defined set of entry/allow/deny globs for a given use case (supported cases: bpf, perf)" },
	{ "entry", 'e', "GLOB", 0,
	  "Glob for entry functions that trigger error stack trace collection" },
	{ "allow", 'a', "GLOB", 0,
	  "Glob for allowed functions captured in error stack trace collection" },
	{ "deny", 'd', "GLOB", 0,
	  "Glob for denied functions ignored during error stack trace collection" },

	/* Function calls trace mode settings */
	{ "trace", 'T', NULL, 0, "Capture and emit function call traces" },

	/* LBR mode settings */
	{ "lbr", 'R', "SPEC", OPTION_ARG_OPTIONAL,
	  "Capture and print LBR entries. You can also tune which LBR records are captured "
	  "by specifying raw LBR flags or using their symbolic aliases: "
	  "any, any_call, any_return (default), cond, call, ind_call, ind_jump, call_stack, "
	  "abort_tx, in_tx, no_tx. "
	  "See enum perf_branch_sample_type in perf_event UAPI (include/uapi/linux/perf_event.h). "
	  "You can combine multiple of them by using --lbr argument multiple times." },
	{ "lbr-max-count", OPT_LBR_MAX_CNT, "N", 0,
	  "Limit number of printed LBRs to N" },

	/* Stack filtering specification */
	{ "pid", 'p', "PID", 0,
	  "Only trace given PID. Can be specified multiple times" },
	{ "no-pid", 'P', "PID", 0,
	  "Skip tracing given PID. Can be specified multiple times" },
	{ "comm", 'n', "COMM", 0,
	  "Only trace processes with given name (COMM). Can be specified multiple times" },
	{ "no-comm", 'N', "COMM", 0,
	  "Skip tracing processes with given name (COMM). Can be specified multiple times" },
	{ "longer", 'L', "MS", 0,
	  "Only emit stacks that took at least a given amount of milliseconds" },
	{ "success-stacks", 'S', NULL, 0,
	  "Emit any stack, successful or not" },
	{ "allow-errors", 'x', "ERROR", 0, "Record stacks only with specified errors" },
	{ "deny-errors", 'X', "ERROR", 0, "Ignore stacks that have specified errors" },

	/* Misc settings */
	{ "kernel", 'k',
	  "PATH", 0, "Path to vmlinux image with DWARF information embedded" },
	{ "symbolize", 's', "LEVEL", OPTION_ARG_OPTIONAL,
	  "Set symbolization settings (-s for line info, -ss for also inline functions, -sn to disable extra symbolization). "
	  "If extra symbolization is requested, retsnoop relies on having vmlinux with DWARF available." },
	{ "intermediate-stacks", 'A', NULL, 0,
	  "Emit all partial (intermediate) stack traces" },
	{ "full-stacks", OPT_FULL_STACKS, NULL, 0,
	  "Emit non-filtered full stack traces" },
	{ "stacks-map-size", OPT_STACKS_MAP_SIZE, "SIZE", 0,
	  "Stacks map size (default 4096)" },
	{ "debug", OPT_DEBUG_FEAT, "FEATURE", 0,
	  "Enable selected debug features. Any set of: multi-kprobe." },
	{},
};

struct preset {
	const char *name;
	const char **entry_globs;
	const char **allow_globs;
	const char **deny_globs;
};

static const char *bpf_entry_globs[];
static const char *bpf_allow_globs[];
static const char *bpf_deny_globs[];

static const char *perf_entry_globs[];
static const char *perf_allow_globs[];
static const char *perf_deny_globs[];

static const struct preset presets[] = {
	{"bpf", bpf_entry_globs, bpf_allow_globs, bpf_deny_globs},
	{"perf", perf_entry_globs, perf_allow_globs, perf_deny_globs},
};

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

static void err_mask_set(__u64 *err_mask, int err_value)
{
	err_mask[err_value / 64] |= 1ULL << (err_value % 64);
}

static int parse_lbr_arg(const char *arg)
{
	long flags, i;
	static struct {
		const char *alias;
		long value;
	} table[] = {
		{"any", PERF_SAMPLE_BRANCH_ANY},/* any branch types */
		{"any_call", PERF_SAMPLE_BRANCH_ANY_CALL},/* any call branch */
		{"any_return", PERF_SAMPLE_BRANCH_ANY_RETURN},/* any return branch */
		{"cond", PERF_SAMPLE_BRANCH_COND},/* conditional branches */
		{"call", PERF_SAMPLE_BRANCH_CALL},/* direct call */
		{"ind_call", PERF_SAMPLE_BRANCH_IND_CALL},/* indirect calls */
		{"ind_jump", PERF_SAMPLE_BRANCH_IND_JUMP},/* indirect jumps */
		{"call_stack", PERF_SAMPLE_BRANCH_CALL_STACK},/* call/ret stack */

		{"abort_tx", PERF_SAMPLE_BRANCH_ABORT_TX},/* transaction aborts */
		{"in_tx", PERF_SAMPLE_BRANCH_IN_TX},/* in transaction */
		{"no_tx", PERF_SAMPLE_BRANCH_NO_TX},/* not in transaction */
	};

	for (i = 0; i < ARRAY_SIZE(table); i++) {
		if (strcmp(table[i].alias, arg) == 0) {
			env.lbr_flags |= table[i].value;
			return 0;
		}
	}

	if (sscanf(arg, "%li", &flags) == 1) {
		env.lbr_flags |= flags;
		return 0;
	}

	fprintf(stderr, "Unrecognized LBR flags. Should be either integer value or one of:");
	for (i = 0; i < ARRAY_SIZE(table); i++) {
		fprintf(stderr, "%s%s", i == 0 ? " " : ", ", table[i].alias);
	}
	fprintf(stderr, ".\n");

	return -EINVAL;
}

static enum debug_feat parse_debug_arg(const char *arg)
{
	int i;
	static struct {
		const char *alias;
		enum debug_feat value;
	} table[] = {
		{"multi-kprobe", DEBUG_MULTI_KPROBE},
	};

	for (i = 0; i < ARRAY_SIZE(table); i++) {
		if (strcmp(table[i].alias, arg) == 0) {
			env.debug_feats |= table[i].value;
			return 0;
		}
	}

	return -EINVAL;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	int i, j, err;

	switch (key) {
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'V':
		env.show_version = true;
		break;
	case 'v':
		env.verbose = true;
		if (arg) {
			if (strcmp(arg, "v") == 0) {
				env.debug = true;
			} else if (strcmp(arg, "vv") == 0) {
				env.debug = true;
				env.debug_extra = true;
			} else {
				fprintf(stderr,
					"Unrecognized verbosity setting '%s', only -v, -vv, and -vvv are supported\n",
					arg);
				return -EINVAL;
			}
		}
		break;
	case 'l':
		env.bpf_logs = true;
		break;
	case 'T':
		env.emit_func_trace = true;
		break;
	case 'c':
		for (i = 0; i < ARRAY_SIZE(presets); i++) {
			const struct preset *p = &presets[i];
			const char *glob;

			if (strcmp(p->name, arg) != 0)
				continue;

			for (j = 0; p->entry_globs[j]; j++) {
				glob = p->entry_globs[j];
				if (append_glob(&env.entry_globs, &env.entry_glob_cnt,
						glob, true /*mandatory*/))
					return -ENOMEM;
			}
			for (j = 0; p->allow_globs[j]; j++) {
				glob = p->allow_globs[j];
				if (append_glob(&env.allow_globs, &env.allow_glob_cnt,
						glob, false /*mandatory*/))
					return -ENOMEM;
			}
			for (j = 0; p->deny_globs[j]; j++) {
				glob = p->deny_globs[j];
				if (append_glob(&env.deny_globs, &env.deny_glob_cnt,
						glob, false /*mandatory*/))
					return -ENOMEM;
			}

			return 0;
		}
		fprintf(stderr, "Unknown preset '%s' specified.\n", arg);
		break;
	case 'a':
		if (arg[0] == '@') {
			err = append_glob_file(&env.allow_globs, &env.allow_glob_cnt,
					       arg + 1, false /*mandatory*/);
		} else if (arg[0] == ':') {
			err = append_str(&env.cu_allow_globs, &env.cu_allow_glob_cnt, arg + 1);
		} else {
			err = append_glob(&env.allow_globs, &env.allow_glob_cnt,
					  arg, false /*mandatory*/);
		}
		if (err)
			return err;
		break;
	case 'd':
		if (arg[0] == '@') {
			err = append_glob_file(&env.deny_globs, &env.deny_glob_cnt,
					       arg + 1, false /*mandatory*/);
		} else if (arg[0] == ':') {
			err = append_str(&env.cu_deny_globs, &env.cu_deny_glob_cnt, arg + 1);
		} else {
			err = append_glob(&env.deny_globs, &env.deny_glob_cnt,
					  arg, false /*mandatory*/);
		}
		if (err)
			return err;
		break;
	case 'e':
		if (arg[0] == '@') {
			err = append_glob_file(&env.entry_globs, &env.entry_glob_cnt,
					       arg + 1, true /*mandatory*/);
		} else if (arg[0] == ':') {
			err = append_str(&env.cu_entry_globs, &env.cu_entry_glob_cnt, arg + 1);
		} else {
			err = append_glob(&env.entry_globs, &env.entry_glob_cnt,
					  arg, true /*mandatory*/);
		}
		if (err)
			return err;
		break;
	case 's':
		env.symb_mode = SYMB_LINEINFO;
		if (arg) {
			if (strcmp(arg, "none") == 0 || strcmp(arg, "n") == 0) {
				env.symb_mode = SYMB_NONE;
			} else if (strcmp(arg, "inlines") == 0 || strcmp(arg, "s") == 0) {
				env.symb_mode |= SYMB_INLINES;
			} else {
				fprintf(stderr,
					"Unrecognized symbolization setting '%s', only -s, -ss (-s inlines), and -sn (-s none) are supported\n",
					arg);
				return -EINVAL;
			}
		}
		break;
	case 'k':
		env.vmlinux_path = arg;
		break;
	case 'n':
		if (arg[0] == '@') {
			err = append_str_file(&env.allow_comms, &env.allow_comm_cnt, arg + 1);
			if (err)
				return err;
		} else if (append_str(&env.allow_comms, &env.allow_comm_cnt, arg)) {
			return -ENOMEM;
		}
		break;
	case 'N':
		if (arg[0] == '@') {
			err = append_str_file(&env.deny_comms, &env.deny_comm_cnt, arg + 1);
			if (err)
				return err;
		} else if (append_str(&env.deny_comms, &env.deny_comm_cnt, arg)) {
			return -ENOMEM;
		}
		break;
	case 'p':
		err = append_pid(&env.allow_pids, &env.allow_pid_cnt, arg);
		if (err)
			return err;
		break;
	case 'P':
		err = append_pid(&env.deny_pids, &env.deny_pid_cnt, arg);
		if (err)
			return err;
		break;
	case 'x':
		err = str_to_err(arg);
		if (err < 0)
			return err;
		/* we start out with all errors allowed, but as soon as we get
		 * the first allowed error specified, we need to reset
		 * all the error to be not allowed by default
		 */
		if (env.allow_error_cnt == 0)
			memset(env.allow_error_mask, 0, sizeof(env.allow_error_mask));
		env.allow_error_cnt++;
		env.has_error_filter = true;
		err_mask_set(env.allow_error_mask, err);
		break;
	case 'X':
		err = str_to_err(arg);
		if (err < 0)
			return err;
		/* we don't need to do anything extra for error blacklist,
		 * because we start with no errors blacklisted by default
		 * anyways, which differs from the logic for error whitelist
		 */
		env.has_error_filter = true;
		err_mask_set(env.deny_error_mask, err);
		break;
	case 'S':
		env.emit_success_stacks = true;
		break;
	case 'M':
		if (env.attach_mode != ATTACH_DEFAULT) {
			fprintf(stderr, "Can't specify -M, -K or -F simultaneously, pick one.\n");
			return -EINVAL;
		}
		env.attach_mode = ATTACH_KPROBE_MULTI;
		break;
	case 'K':
		if (env.attach_mode != ATTACH_DEFAULT) {
			fprintf(stderr, "Can't specify -M, -K or -F simultaneously, pick one.\n");
			return -EINVAL;
		}
		env.attach_mode = ATTACH_KPROBE_SINGLE;
		break;
	case 'F':
		if (env.attach_mode != ATTACH_DEFAULT) {
			fprintf(stderr, "Can't specify -M, -K or -F simultaneously, pick one.\n");
			return -EINVAL;
		}
		env.attach_mode = ATTACH_FENTRY;
		break;
	case 'A':
		env.emit_intermediate_stacks = true;
		break;
	case 'L':
		errno = 0;
		env.longer_than_ms = strtol(arg, NULL, 10);
		if (errno || env.longer_than_ms <= 0) {
			fprintf(stderr, "Invalid -L duration: %d\n", env.longer_than_ms);
			return -EINVAL;
		}
		break;
	case 'R':
		env.use_lbr = true;
		if (arg && parse_lbr_arg(arg))
			return -EINVAL;
		break;
	case OPT_LBR_MAX_CNT:
		errno = 0;
		env.lbr_max_cnt = strtol(arg, NULL, 10);
		if (errno || env.lbr_max_cnt < 0) {
			fprintf(stderr, "Invalid LBR maximum count: %d\n", env.lbr_max_cnt);
			return -EINVAL;
		}
		break;
	case OPT_FULL_STACKS:
		env.emit_full_stacks = true;
		break;
	case OPT_STACKS_MAP_SIZE:
		errno = 0;
		env.stacks_map_sz = strtol(arg, NULL, 10);
		if (errno || env.stacks_map_sz < 0) {
			fprintf(stderr, "Invalid stacks map size: %d\n", env.stacks_map_sz);
			return -EINVAL;
		}
		break;
	case OPT_DRY_RUN:
		env.dry_run = true;
		break;
	case OPT_DEBUG_FEAT:
		if (parse_debug_arg(arg))
			return -EINVAL;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
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

static __u64 ktime_off;

static void calibrate_ktime(void)
{
	int i;
	struct timespec t1, t2, t3;
	__u64 best_delta = 0, delta, ts;

	for (i = 0; i < 10; i++) {
		clock_gettime(CLOCK_REALTIME, &t1);
		clock_gettime(CLOCK_MONOTONIC, &t2);
		clock_gettime(CLOCK_REALTIME, &t3);

		delta = timespec_to_ns(&t3) - timespec_to_ns(&t1);
		ts = (timespec_to_ns(&t3) + timespec_to_ns(&t1)) / 2;

		if (i == 0 || delta < best_delta) {
			best_delta = delta;
			ktime_off = ts - timespec_to_ns(&t2);
		}
	}
}

/* PRESETS */

static const char *bpf_entry_globs[] = {
	"*_sys_bpf",
	NULL,
};

static const char *bpf_allow_globs[] = {
	"*bpf*",
	"*btf*",
	"do_check*",
	"reg_*",
	"check_*",
	"resolve_*",
	"convert_*",
	"adjust_*",
	"sanitize_*",
	"map_*",
	"ringbuf_*",
	"array_*",
	"__vmalloc_*",
	"__alloc*",
	"pcpu_*",
	"memdup_*",
	"stack_map_*",
	"htab_*",
	"generic_map_*",
	"*copy_from*",
	"*copy_to*",
	NULL,
};

static const char *bpf_deny_globs[] = {
	"bpf_get_smp_processor_id",
	"bpf_get_current_pid_tgid",
	"*migrate*",
	"rcu_read_lock*",
	"rcu_read_unlock*",

	/* too noisy */
	"bpf_lsm_*",
	"check_cfs_rq_runtime",
	"find_busiest_group",
	"find_vma*",

	/* non-failing */
	"btf_sec_info_cmp",

	/* can't attach for some reason */
	"copy_to_user_nofault",

	NULL,
};

static const char *perf_entry_globs[] = {
	"*_sys__perf_event_open",
	"perf_ioctl",
	NULL,
};

static const char *perf_allow_globs[] = {
	"*perf_*",
	NULL,
};

static const char *perf_deny_globs[] = {
	NULL,
};

/* fexit logical stack trace item */
struct fstack_item {
	const struct mass_attacher_func_info *finfo;
	int flags;
	const char *name;
	long res;
	long lat;
	bool finished;
	bool stitched;
	bool err_start;
};

static bool is_err_in_mask(__u64 *err_mask, int err)
{
	if (err < 0)
		err = -err;
	if (err >= MAX_ERR_CNT)
		return false;
	return (err_mask[err / 64] >> (err % 64)) & 1;
}

static const struct func_info *func_info(const struct ctx *ctx, __u32 id)
{
	return &ctx->skel->data_func_infos->func_infos[id];
}

static bool should_report_stack(struct ctx *ctx, const struct call_stack *s)
{
	int i, id, flags, res;
	bool allowed = false;

	if (!env.has_error_filter)
		return true;

	for (i = 0; i < s->max_depth; i++) {
		id = s->func_ids[i];
		flags = func_info(ctx, id)->flags;

		if (flags & FUNC_CANT_FAIL)
			continue;

		res = s->func_res[i];
		if (flags & FUNC_NEEDS_SIGN_EXT)
			res = (long)(int)res;

		if (res == 0 && !(flags & FUNC_RET_PTR))
			continue;

		/* if error is blacklisted, reject immediately */
		if (is_err_in_mask(env.deny_error_mask, res))
			return false;
		/* if error is whitelisted, mark as allowed; but we need to
		 * still see if any other errors in the stack are blacklisted
		 */
		if (is_err_in_mask(env.allow_error_mask, res))
			allowed = true;
	}

	/* no stitched together stack */
	if (s->max_depth + 1 != s->saved_depth)
		return allowed;

	for (i = s->saved_depth - 1; i < s->saved_max_depth; i++) {
		id = s->saved_ids[i];
		flags = func_info(ctx, id)->flags;

		if (flags & FUNC_CANT_FAIL)
			continue;

		res = s->func_res[i];
		if (flags & FUNC_NEEDS_SIGN_EXT)
			res = (long)(int)res;

		if (res == 0 && !(flags & FUNC_RET_PTR))
			continue;

		/* if error is blacklisted, reject immediately */
		if (is_err_in_mask(env.deny_error_mask, res))
			return false;
		/* if error is whitelisted, mark as allowed; but we need to
		 * still see if any other errors in the stack are blacklisted
		 */
		if (is_err_in_mask(env.allow_error_mask, res))
			allowed = true;
	}

	return allowed;
}

static int filter_fstack(struct ctx *ctx, struct fstack_item *r, const struct call_stack *s)
{
	const struct mass_attacher_func_info *finfo;
	struct mass_attacher *att = ctx->att;
	struct fstack_item *fitem;
	const char *fname;
	int i, id, flags, cnt;

	for (i = 0, cnt = 0; i < s->max_depth; i++, cnt++) {
		id = s->func_ids[i];
		flags = func_info(ctx, id)->flags;
		finfo = mass_attacher__func(att, id);
		fname = finfo->name;

		fitem = &r[cnt];
		fitem->finfo = finfo;
		fitem->flags = flags;
		fitem->name = fname;
		fitem->stitched = false;
		if (i >= s->depth) {
			fitem->finished = true;
			fitem->lat = s->func_lat[i];
		} else {
			fitem->finished = false;
			fitem->lat = 0;
		}
		if (flags & FUNC_NEEDS_SIGN_EXT)
			fitem->res = (long)(int)s->func_res[i];
		else
			fitem->res = s->func_res[i];
		fitem->lat = s->func_lat[i];
	}

	/* no stitched together stack */
	if (s->max_depth + 1 != s->saved_depth)
		return cnt;

	for (i = s->saved_depth - 1; i < s->saved_max_depth; i++, cnt++) {
		id = s->saved_ids[i];
		flags = func_info(ctx, id)->flags;
		finfo = mass_attacher__func(att, id);
		fname = finfo->name;

		fitem = &r[cnt];
		fitem->finfo = finfo;
		fitem->flags = flags;
		fitem->name = fname;
		fitem->stitched = true;
		fitem->finished = true;
		fitem->lat = s->saved_lat[i];
		if (flags & FUNC_NEEDS_SIGN_EXT)
			fitem->res = (long)(int)s->saved_res[i];
		else
			fitem->res = s->saved_res[i];
	}

	return cnt;
}

/* actual kernel stack trace item */
struct kstack_item {
	const struct ksym *ksym;
	long addr;
	bool filtered;
};

static bool is_bpf_tramp(const struct kstack_item *item)
{
	static char bpf_tramp_pfx[] = "bpf_trampoline_";

	if (!item->ksym)
		return false;

	return strncmp(item->ksym->name, bpf_tramp_pfx, sizeof(bpf_tramp_pfx) - 1) == 0
	       && isdigit(item->ksym->name[sizeof(bpf_tramp_pfx)]);
}

/* recognize stack trace entries representing BPF program, e.g.:
 * bpf_prog_28efb01f5c962284_my_prog
 */
static bool is_bpf_prog(const struct kstack_item *item)
{
	static char bpf_prog_pfx[] = "bpf_prog_";
	const char *s;
	int i;
	bool has_digits = false;

	if (!item->ksym)
		return false;

	s = item->ksym->name;
	if (strncmp(s, bpf_prog_pfx, sizeof(bpf_prog_pfx) - 1) != 0)
		return false;

	for (i = sizeof(bpf_prog_pfx); s[i] && s[i] != '_'; i++ ) {
		if (!isxdigit(s[i]))
			return false;

		if (isdigit(s[i]))
			has_digits = true;
	}

	return has_digits;
}

#define FTRACE_OFFSET 0x5

static int filter_kstack(struct ctx *ctx, struct kstack_item *r, const struct call_stack *s)
{
	struct ksyms *ksyms = ctx->ksyms;
	int i, n, p;

	/* lookup ksyms and reverse stack trace to match natural call order */
	n = s->kstack_sz / 8;
	for (i = 0; i < n; i++) {
		struct kstack_item *item = &r[n - i - 1];

		item->addr = s->kstack[i];
		item->filtered = false;
		item->ksym = ksyms__map_addr(ksyms, item->addr);
		if (!item->ksym)
			continue;
	}

	/* perform addiitonal post-processing to filter out bpf_trampoline and
	 * bpf_prog symbols, fixup fexit patterns, etc
	 */
	for (i = 0, p = 0; i < n; i++) {
		struct kstack_item *item = &r[p];

		*item = r[i];

		if (!item->ksym) {
			p++;
			continue;
		}

		/* Ignore bpf_trampoline frames and fix up stack traces.
		 * When fexit program happens to be inside the stack trace,
		 * a following stack trace pattern will be apparent (taking
		 * into account inverted order of frames * which we did few
		 * lines above):
		 *     ffffffff8116a3d5 bpf_map_alloc_percpu+0x5
		 *     ffffffffa16db06d bpf_trampoline_6442494949_0+0x6d
		 *     ffffffff8116a40f bpf_map_alloc_percpu+0x3f
		 * 
		 * bpf_map_alloc_percpu+0x5 is real, by it just calls into the
		 * trampoline, which them calls into original call
		 * (bpf_map_alloc_percpu+0x3f). So the last item is what
		 * really matters, everything else is just a distraction, so
		 * try to detect this and filter it out. Unless we are in
		 * full-stacks mode, of course, in which case we live a hint
		 * that this would be filtered out (helps with debugging
		 * overall), but otherwise is preserved.
		 */
		if (i + 2 < n && is_bpf_tramp(&r[i + 1])
		    && r[i].ksym == r[i + 2].ksym
		    && r[i].addr - r[i].ksym->addr == FTRACE_OFFSET) {
			if (env.emit_full_stacks) {
				item->filtered = true;
				p++;
				continue;
			}

			/* skip two elements and process useful item */
			*item = r[i + 2];
			continue;
		}

		/* Ignore bpf_trampoline and bpf_prog in stack trace, those
		 * are most probably part of our own instrumentation, but if
		 * not, you can still see them in full-stacks mode.
		 * Similarly, remove bpf_get_stack_raw_tp, which seems to be
		 * always there due to call to bpf_get_stack() from BPF
		 * program.
		 */
		if (is_bpf_tramp(&r[i]) || is_bpf_prog(&r[i])
		    || strcmp(r[i].ksym->name, "bpf_get_stack_raw_tp") == 0) {
			if (env.emit_full_stacks) {
				item->filtered = true;
				p++;
				continue;
			}

			if (i + 1 < n)
				*item = r[i + 1];
			continue;
		}

		p++;
	}

	return p;
}

static int detect_linux_src_loc(const char *path)
{
	static const char *linux_dirs[] = {
		"arch/", "block/", "certs/", "crypto/", "drivers/", "fs/",
		"include/", "init/", "io_uring/", "ipc/", "kernel/", "lib/",
		"mm/", "net/", "rust/", "scripts/", "security/", "sound/",
		"tools/", "usr/", "virt/",
	};
	int i;
	char *p;

	for (i = 0; i < ARRAY_SIZE(linux_dirs); i++) {
		p = strstr(path, linux_dirs[i]);
		if (p)
			return p - path;
	}

	return 0;
}

/*
 * Typical output in "default" mode:
 *                      entry_SYSCALL_64_after_hwframe+0x44  (arch/x86/entry/entry_64.S:112:0)
 *                      do_syscall_64+0x2d                   (arch/x86/entry/common.c:46:12)
 *    11us [-ENOENT]    __x64_sys_bpf+0x1c                   (kernel/bpf/syscall.c:4749:1)
 *    10us [-ENOENT]    __sys_bpf+0x1a42                     (kernel/bpf/syscall.c:4632:9)
 *                      . map_lookup_elem                    (kernel/bpf/syscall.c:1113:5)
 * !   0us [-ENOENT]    bpf_map_copy_value
 *
 */
struct stack_item {
	char marks[2]; /* spaces or '!' and/or '*' */

	char dur[20];  /* duration, e.g. '11us' or '...' for incomplete stack */
	int dur_len;   /* number of characters used for duration output */

	char err[24];  /* returned error, e.g., '-ENOENT' or '...' for incomplete stack */
	int err_len;   /* number of characters used for error output */

	/* resolved symbol name, but also can include:
	 *   - full captured address, if --full-stacks option is enabled;
	 *   - inline marker, '. ', prepended to symbol name;
	 *   - offset within function, like '+0x1c'.
	 * Examples:
	 *   - 'ffffffff81c00068 entry_SYSCALL_64_after_hwframe+0x44';
	 *   - '__x64_sys_bpf+0x1c';
	 *   - '. map_lookup_elem'.
	 */
	char sym[124];
	int sym_len;

	/* source code location of resolved function, e.g.:
	 *   - 'kernel/bpf/syscall.c:4749:1';
	 *   - 'arch/x86/entry/entry_64.S:112:0'.
	 * Could also have prepended original function name if it doesn't
	 * match resolved kernel symbol, e.g.:
	 *   'my_actual_func @ arch/x86/entry/entry_64.S:112:0'.
	 */
	char src[252];
	int src_len;
};

struct stack_items_cache
{
	struct stack_item *items;
	size_t cnt;
	size_t cap;
};

static struct stack_items_cache stack_items1, stack_items2;

static struct stack_item *get_stack_item(struct stack_items_cache *cache)
{
	struct stack_item *s;

	if (cache->cnt == cache->cap) {
		size_t new_cap = cache->cap * 3 / 2;
		void *tmp;

		if (new_cap < 32)
			new_cap = 32;

		tmp = realloc(cache->items, new_cap * sizeof(*s));
		if (!tmp)
			return NULL;

		cache->items = tmp;
		memset(cache->items + cache->cap, 0, (new_cap - cache->cap) * sizeof(*s));
		cache->cap = new_cap;
	}

	s = &cache->items[cache->cnt++];

	s->dur_len = s->err_len = s->sym_len = s->src_len = 0;
	s->dur[0] = s->err[0] = s->sym[0] = s->src[0] = 0;
	s->marks[0] = s->marks[1] = ' ';

	return s;
}

#define snappendf(dst, fmt, args...)							\
	dst##_len += snprintf(dst + dst##_len,						\
			      sizeof(dst) < dst##_len ? 0 : sizeof(dst) - dst##_len,	\
			      fmt, ##args)

struct func_trace_item {
	long ts;
	long func_lat;
	int func_id;
	int depth; /* 1-based, negative means exit from function */
	int seq_id;
	long func_res;
};

struct func_trace {
	int pid;
	int cnt;
	struct func_trace_item *entries;
};

static struct hashmap *func_traces_hash;

static size_t func_traces_hasher(long key, void *ctx)
{
	return (size_t)key;
}

static bool func_traces_equal(long key1, long key2, void *ctx)
{
	return key1 == key2;
}

static int init_func_traces(void)
{
	func_traces_hash = hashmap__new(func_traces_hasher, func_traces_equal, NULL);
	if (!func_traces_hash)
		return -ENOMEM;

	return 0;
}

static void free_func_trace(struct func_trace *ft)
{
	if (!ft)
		return;

	free(ft->entries);
	free(ft);
}

static void free_func_traces(void)
{
	struct hashmap_entry *e;
	int bkt;

	if (!func_traces_hash)
		return;

	hashmap__for_each_entry(func_traces_hash, e, bkt) {
		free_func_trace(e->pvalue);
	}

	hashmap__free(func_traces_hash);
}

static void purge_func_trace(struct ctx *ctx, int pid)
{
	const void *k = (const void *)(uintptr_t)pid;
	struct func_trace *ft;

	if (!env.emit_func_trace)
		return;

	if (hashmap__delete(func_traces_hash, k, NULL, &ft))
		free_func_trace(ft);
}

static int handle_func_trace_start(struct ctx *ctx, const struct func_trace_start *r)
{
	purge_func_trace(ctx, r->pid);

	return 0;
}

static int handle_func_trace_entry(struct ctx *ctx, const struct func_trace_entry *r)
{
	const void *k = (const void *)(uintptr_t)r->pid;
	struct func_trace *ft;
	struct func_trace_item *fti;
	void *tmp;

	if (!hashmap__find(func_traces_hash, k, &ft)) {
		ft = calloc(1, sizeof(*ft));
		if (!ft || hashmap__add(func_traces_hash, k, ft)) {
			fprintf(stderr, "Failed to allocate memory for new function trace entry!\n");
			return -ENOMEM;
		}

		ft->pid = r->pid;
	}

	tmp = realloc(ft->entries, (ft->cnt + 1) * sizeof(ft->entries[0]));
	if (!tmp)
		return -ENOMEM;
	ft->entries = tmp;

	fti = &ft->entries[ft->cnt];
	fti->ts = r->ts;
	fti->func_id = r->func_id;
	fti->depth = r->type == REC_FUNC_TRACE_ENTRY ? r->depth : -r->depth;
	fti->seq_id = r->seq_id;
	fti->func_lat = r->func_lat;
	fti->func_res = r->func_res;

	ft->cnt++;

	return 0;
}

static void prepare_func_res(struct stack_item *s, long res, int func_flags);

static char underline[512]; /* fill be filled with header underline char */
static char spaces[512]; /* fill be filled with spaces */

static void add_missing_records_msg(struct stack_items_cache *cache, int miss_cnt)
{
	struct stack_item *s;

	s = get_stack_item(cache);
	if (!s) {
		fprintf(stderr, "Ran out of formatting space, some data will be omitted!\n");
		return;
	}

	snappendf(s->src, "\u203C ... missing %d record%s ...",
		  miss_cnt, miss_cnt == 1 ? "" : "s");
	snappendf(s->dur, "...");
	snappendf(s->err, "...");
}

static void prepare_ft_items(struct ctx *ctx, struct stack_items_cache *cache,
			     const struct call_stack *cs)
{
	const void *k = (const void *)(uintptr_t)cs->pid;
	const struct mass_attacher_func_info *finfo;
	const char *sp, *mark;
	struct stack_item *s;
	struct func_trace *ft;
	struct func_trace_item *f, *fn;
	int i, d, last_seq_id = -1;

	if (!hashmap__find(func_traces_hash, k, &ft))
		return;

	cache->cnt = 0;

	for (i = 0; i < ft->cnt; last_seq_id = f->seq_id, i++) {
		f = &ft->entries[i];
		finfo = mass_attacher__func(ctx->att, f->func_id);
		d = f->depth > 0 ? f->depth : -f->depth;
		sp = spaces + sizeof(spaces) - 1 - 4 * min(d - 1, 30);

		if (f->seq_id > last_seq_id + 1)
			add_missing_records_msg(cache, f->seq_id - last_seq_id - 1);

		s = get_stack_item(cache);
		if (!s) {
			fprintf(stderr, "Ran out of formatting space, some data will be omitted!\n");
			break;
		}

		/* see if we can collapse leaf function entry/exit into one */
		fn = &ft->entries[i + 1];
		if (i + 1 < ft->cnt &&
		    fn->seq_id == f->seq_id + 1 && /* consecutive items */
		    fn->func_id == f->func_id && /* same function */
		    f->depth > 0 && f->depth == -fn->depth /* matching entry and exit */) {
			f = fn; /* use exit item as main data source */
			i += 1; /* skip exit entry */
		}

		if (f == fn)		  /* collapsed leaf */
			mark = "\u2194 "; /* unicode <-> character */
		else if (f->depth > 0)	  /* entry */
			mark = "\u2192 "; /* unicode -> character */
		else			  /* exit */
			mark = "\u2190 "; /* unicode <- character */

		/* store function name and space indentation in src, as we
		 * might need a bunch of extra space due to deep nestedness
		 */
		snappendf(s->src, "%s%s%s", sp, mark, finfo->name);

		if (f->depth < 0) {
			snappendf(s->dur, "%.3fus", f->func_lat / 1000.0);
			prepare_func_res(s, f->func_res, func_info(ctx, f->func_id)->flags);
		}
	}

	if (cs->next_seq_id != last_seq_id + 1)
		add_missing_records_msg(cache, cs->next_seq_id - last_seq_id - 1);

	purge_func_trace(ctx, ft->pid);
}

static void print_ft_items(struct ctx *ctx, const struct stack_items_cache *cache)
{
	int dur_len = 5, res_len = 0, src_len = 0, i;
	const struct stack_item *s;

	printf("\n");

	/* calculate desired length of each auto-sized part of the output */
	for (i = 0, s = cache->items; i < cache->cnt; i++, s++) {
		dur_len = max(dur_len, s->dur_len);
		res_len = max(res_len, s->err_len);
		src_len = max(src_len, s->src_len);
	}
	/* the whole +2 and -2 business is due to the use of unicode characters */
	src_len = max(src_len, 2 + sizeof("FUNCTION CALL TRACE") - 1);
	res_len = max(res_len, sizeof("RESULT") - 1);
	dur_len = max(dur_len, sizeof("DURATION") - 1);

	printf("%-*s   %-*s  %*s\n",
	       src_len - 2, "FUNCTION CALL TRACE",
	       res_len, "RESULT", dur_len, "DURATION");
	printf("%-.*s   %-.*s  %.*s\n",
	       src_len - 2, underline,
	       res_len, underline,
	       dur_len, underline);

	/* emit line by line taking into account calculated lengths of each column */
	for (i = 0, s = cache->items; i < cache->cnt; i++, s++) {
		printf("%-*s   %-*s  %*s\n",
		       src_len, s->src,
		       res_len, s->err,
		       dur_len, s->dur);
	}

}

static void prepare_func_res(struct stack_item *s, long res, int func_flags)
{
	const char *errstr;

	if (func_flags & FUNC_RET_VOID) {
		snappendf(s->err, "[void]");
		return;
	}

	if (func_flags & FUNC_NEEDS_SIGN_EXT)
		res = (long)(int)res;

	if (res >= 0 || res < -MAX_ERRNO) {
		if (func_flags & FUNC_RET_PTR)
			snappendf(s->err, res == 0 ? "[NULL]" : "[%p]", (const void *)res);
		else if (func_flags & FUNC_RET_BOOL)
			snappendf(s->err, res == 0 ? "[false]" : "[true]");
		else if (res >= -1024 * 1024 * 1024  && res < 1024 * 1024 /* random heuristic */)
			snappendf(s->err, "[%ld]", res);
		else
			snappendf(s->err, "[0x%lx]", res);
	} else {
		errstr = err_to_str(res);
		if (errstr)
			snappendf(s->err, "[-%s]", errstr);
		else
			snappendf(s->err, "[%ld]", res);
	}
}

static void prepare_stack_items(struct ctx *ctx, const struct fstack_item *fitem,
				const struct kstack_item *kitem)
{
	static struct a2l_resp resps[64];
	struct a2l_resp *resp = NULL;
	int symb_cnt = 0, i, line_off;
	const char *fname;
	struct stack_item *s;

	if (env.symb_mode != SYMB_NONE && ctx->a2l && kitem && !kitem->filtered) {
		long addr = kitem->addr;

		if (kitem->ksym && kitem->ksym && kitem->ksym->addr - kitem->addr == FTRACE_OFFSET)
			addr -= FTRACE_OFFSET;

		symb_cnt = addr2line__symbolize(ctx->a2l, addr, resps);
		if (symb_cnt < 0)
			symb_cnt = 0;
		if (symb_cnt > 0)
			resp = &resps[symb_cnt - 1];
	}

	s = get_stack_item(&stack_items1);
	if (!s) {
		fprintf(stderr, "Ran out of formatting space, some data will be omitted!\n");
		return;
	}

	/* kitem == NULL should be rare, either a bug or we couldn't get valid kernel stack trace */
	s->marks[0] = kitem ? ' ' : '!';
	s->marks[1] = (fitem && fitem->stitched) ? '*' : ' ';

	if (fitem && !fitem->finished) {
		snappendf(s->dur, "...");
		snappendf(s->err, "[...]");
	} else if (fitem) {
		snappendf(s->dur, "%ldus", fitem->lat / 1000);
		prepare_func_res(s, fitem->res, fitem->flags);
	}

	if (env.emit_full_stacks) {
		if (kitem)
			snappendf(s->sym, "%c%016lx ", kitem->filtered ? '~' : ' ',  kitem->addr);
		else
			snappendf(s->sym, " %*s ", 16, "");
	}

	if (kitem && kitem->ksym)
		fname = kitem->ksym->name;
	else if (fitem)
		fname = fitem->name;
	else
		fname = "";
	snappendf(s->sym, "%s", fname);
	if (kitem && kitem->ksym)
		snappendf(s->sym, "+0x%lx", kitem->addr - kitem->ksym->addr);
	if (symb_cnt) {
		line_off = detect_linux_src_loc(resp->line);

		snappendf(s->src, "(");
		if (strcmp(fname, resp->fname) != 0)
			snappendf(s->src, "%s @ ", resp->fname);
		snappendf(s->src, "%s)", resp->line + line_off);
	}

	/* append inlined calls */
	for (i = 1, resp--; i < symb_cnt; i++, resp--) {
		s = get_stack_item(&stack_items1);
		if (!s) {
			fprintf(stderr, "Ran out of formatting space, some data will be omitted!\n");
			return;
		}

		line_off = detect_linux_src_loc(resp->line);

		snappendf(s->sym, "%*s. %s", env.emit_full_stacks ? 18 : 0, "", resp->fname);
		snappendf(s->src, "(%s)", resp->line + line_off);
	}
}

static void print_stack_items(const struct stack_items_cache *cache)
{
	int dur_len = 5, err_len = 0, sym_len = 0, src_len = 0, i;
	const struct stack_item *s;

	/* calculate desired length of each auto-sized part of the output */
	for (i = 0, s = cache->items; i < cache->cnt; i++, s++) {
		dur_len = max(dur_len, s->dur_len);
		err_len = max(err_len, s->err_len);
		sym_len = max(sym_len, s->sym_len);
		src_len = max(src_len, s->src_len);
	}

	printf("\n");

	/* emit line by line taking into account calculated lengths of each column */
	for (i = 0, s = cache->items; i < cache->cnt; i++, s++) {
		printf("%c%c %*s %-*s  %-*s  %-*s\n",
		       s->marks[0], s->marks[1],
		       dur_len, s->dur, err_len, s->err,
		       sym_len, s->sym, src_len, s->src);
	}
}

static void prepare_lbr_items(struct ctx *ctx, long addr, struct stack_items_cache *cache)
{
	static struct a2l_resp resps[64];
	struct a2l_resp *resp = NULL;
	int symb_cnt = 0, line_off, i;
	const struct ksym *ksym;
	struct stack_item *s;

	s = get_stack_item(cache);
	if (!s) {
		fprintf(stderr, "Ran out of formatting space, some data will be omitted!\n");
		return;
	}

	if (env.emit_full_stacks)
		snappendf(s->sym, "%016lx ", addr);

	ksym = ksyms__map_addr(ctx->ksyms, addr);
	if (ksym)
		snappendf(s->sym, "%s+0x%lx", ksym->name, addr - ksym->addr);

	if (!ctx->a2l || env.symb_mode == SYMB_NONE)
		return;

	symb_cnt = addr2line__symbolize(ctx->a2l, addr, resps);
	if (symb_cnt <= 0)
		return;

	resp = &resps[symb_cnt - 1];
	line_off = detect_linux_src_loc(resp->line);

	snappendf(s->src, "(");
	if (strcmp(ksym->name, resp->fname) != 0)
		snappendf(s->src, "%s @ ", resp->fname);
	snappendf(s->src, "%s)", resp->line + line_off);

	for (i = 1, resp--; i < symb_cnt; i++, resp--) {
		line_off = detect_linux_src_loc(resp->line);

		s = get_stack_item(cache);
		if (!s) {
			fprintf(stderr, "Ran out of formatting space, some data will be omitted!\n");
			return;
		}
		if (env.emit_full_stacks)
			snappendf(s->sym, "%*s ", 16, "");
		snappendf(s->sym, ". %s", resp->fname);
		snappendf(s->src, "(%s)", resp->line + line_off);
	}
}

static void print_lbr_items(int lbr_from, int lbr_to,
			    const struct stack_items_cache *cache1, int rec_cnts1[MAX_LBR_ENTRIES],
			    const struct stack_items_cache *cache2, int rec_cnts2[MAX_LBR_ENTRIES])
{
	int sym_len1 = 0, sym_len2 = 0, src_len1 = 0, src_len2 = 0, i, j, k;
	const struct stack_item *s1, *s2;

	/* calculate desired length of each auto-sized part of the output */
	for (i = 0, s1 = cache1->items; i < cache1->cnt; i++, s1++) {
		sym_len1 = max(sym_len1, s1->sym_len);
		src_len1 = max(src_len1, s1->src_len);
	}
	for (j = 0, s2 = cache2->items; j < cache2->cnt; j++, s2++) {
		sym_len2 = max(sym_len2, s2->sym_len);
		src_len2 = max(src_len2, s2->src_len);
	}

	printf("\n");

	/* emit each LBR record (which can contain multiple lines) */
	for (i = 0, j = 0, k = lbr_from; k >= lbr_to; k--) {
		bool first = true;

		while (i < rec_cnts1[k] || j < rec_cnts2[k]) {
			s1 = i < rec_cnts1[k] ? &cache1->items[i++] : NULL;
			s2 = j < rec_cnts2[k] ? &cache2->items[j++] : NULL;

			if (first)
				printf("[#%02d] ", k);
			else
				printf("      ");
			printf("%-*s %-*s  %s  %-*s %-*s\n",
			       sym_len1, s1 ? s1->sym : "",
			       src_len1, s1 ? s1->src : "",
			       first ? "->" : "  ",
			       sym_len2, s2 ? s2->sym : "",
			       src_len2, s2 ? s2->src : "");

			first = false;
		}
	}
}


static bool lbr_matches(unsigned long addr, unsigned long start, unsigned long end)
{
	if (!start)
		return true;

	return start <= addr && addr < end;
}

static int handle_call_stack(struct ctx *dctx, const struct call_stack *s)
{
	static struct fstack_item fstack[MAX_FSTACK_DEPTH];
	static struct kstack_item kstack[MAX_KSTACK_DEPTH];
	const struct fstack_item *fitem;
	const struct kstack_item *kitem;
	int i, j, fstack_n, kstack_n;
	char ts1[64], ts2[64];

	if (!s->is_err && !env.emit_success_stacks) {
		purge_func_trace(dctx, s->pid);
		return 0;
	}

	if (s->is_err && env.has_error_filter && !should_report_stack(dctx, s)) {
		purge_func_trace(dctx, s->pid);
		return 0;
	}

	if (env.debug) {
		printf("GOT %s STACK (depth %u):\n", s->is_err ? "ERROR" : "SUCCESS", s->max_depth);
		printf("DEPTH %d MAX DEPTH %d SAVED DEPTH %d MAX SAVED DEPTH %d\n",
				s->depth, s->max_depth, s->saved_depth, s->saved_max_depth);
	}

	fstack_n = filter_fstack(dctx, fstack, s);
	if (fstack_n < 0) {
		fprintf(stderr, "FAILURE DURING FILTERING FUNCTION STACK!!! %d\n", fstack_n);
		purge_func_trace(dctx, s->pid);
		return -1;
	}
	kstack_n = filter_kstack(dctx, kstack, s);
	if (kstack_n < 0) {
		fprintf(stderr, "FAILURE DURING FILTERING KERNEL STACK!!! %d\n", kstack_n);
		purge_func_trace(dctx, s->pid);
		return -1;
	}
	if (env.debug) {
		printf("FSTACK (%d items):\n", fstack_n);
		printf("KSTACK (%d items out of original %ld):\n", kstack_n, s->kstack_sz / 8);
	}

	ts_to_str(s->start_ts + ktime_off, ts1, sizeof(ts1));
	ts_to_str(s->emit_ts + ktime_off, ts2, sizeof(ts2));
	printf("%s -> %s TID/PID %d/%d (%s/%s):\n", ts1, ts2, s->pid, s->tgid,  s->task_comm, s->proc_comm);

	/* Emit more verbose outputs before more succinct and high signal output.
	 * Func trace goes first, then LBR, then (error) stack trace, each
	 * conditional on being enabled to be collected and output
	 */

	/* Emit detailed function calls trace, but only if we have completed
	 * call stack trace (depth == 0)
	 */
	if (env.emit_func_trace && s->depth == 0) {
		prepare_ft_items(dctx, &stack_items1, s);
		print_ft_items(dctx, &stack_items1);
	}

	/* LBR output */
	if (env.use_lbr) {
		unsigned long start = 0, end = 0;
		int lbr_cnt, lbr_from, lbr_to = 0;
		int rec_cnts1[MAX_LBR_ENTRIES] = {};
		int rec_cnts2[MAX_LBR_ENTRIES] = {};
		bool found_useful_lbrs = false;

		if (s->lbrs_sz < 0) {
			fprintf(stderr, "Failed to capture LBR entries: %ld\n", s->lbrs_sz);
			goto out;
		}

		if (fstack_n > 0) {
			fitem = &fstack[fstack_n - 1];
			if (fitem->finfo->size) {
				start = fitem->finfo->addr;
				end = fitem->finfo->addr + fitem->finfo->size;
			}
		}

		lbr_cnt = s->lbrs_sz / sizeof(struct perf_branch_entry);
		lbr_from = lbr_cnt - 1;

		if (!env.emit_full_stacks) {
			/* Filter out last few irrelevant LBRs that captured
			 * internal BPF/kprobe/perf jumps. For that, find the
			 * first LBR record that overlaps with the last traced
			 * function. All the records after that are assumed
			 * relevant.
			 */
			for (i = 0, lbr_to = 0; i < lbr_cnt; i++, lbr_to++) {
				if (lbr_matches(s->lbrs[i].from, start, end) ||
				    lbr_matches(s->lbrs[i].to, start, end)) {
					found_useful_lbrs = true;
					break;
				}
			}
			if (!found_useful_lbrs)
				lbr_to = 0;
		}

		if (env.lbr_max_cnt && lbr_from - lbr_to + 1 > env.lbr_max_cnt)
			lbr_from = min(lbr_cnt - 1, lbr_to + env.lbr_max_cnt - 1);

		stack_items1.cnt = 0;
		stack_items2.cnt = 0;
		for (i = lbr_from; i >= lbr_to; i--) {
			prepare_lbr_items(dctx, s->lbrs[i].from, &stack_items1);
			prepare_lbr_items(dctx, s->lbrs[i].to, &stack_items2);

			rec_cnts1[i] = stack_items1.cnt;
			rec_cnts2[i] = stack_items2.cnt;
		}

		print_lbr_items(lbr_from, lbr_to,
				&stack_items1, rec_cnts1,
				&stack_items2, rec_cnts2);

		if (!env.emit_full_stacks && !found_useful_lbrs)
			printf("[LBR] No relevant LBR data were captured, showing unfiltered LBR stack!\n");
	}

	/* Emit combined fstack/kstack + errors stack trace */
	stack_items1.cnt = 0;

	i = 0;
	j = 0;
	while (i < fstack_n) {
		fitem = &fstack[i];
		kitem = j < kstack_n ? &kstack[j] : NULL;

		if (!kitem) {
			/* this shouldn't happen unless we got no kernel stack
			 * or there is some bug
			 */
			prepare_stack_items(dctx, fitem, NULL);
			i++;
			continue;
		}

		/* exhaust unknown kernel stack items, assuming we should find
		 * kstack_item matching current fstack_item eventually, which
		 * should be the case when kernel stack trace is correct
		 */
		if (!kitem->ksym || kitem->filtered
		    || strcmp(kitem->ksym->name, fitem->name) != 0) {
			prepare_stack_items(dctx, NULL, kitem);
			j++;
			continue;
		}

		/* happy case, lots of info, yay */
		prepare_stack_items(dctx, fitem, kitem);
		i++;
		j++;
		continue;
	}

	for (; j < kstack_n; j++) {
		prepare_stack_items(dctx, NULL, &kstack[j]);
	}

	print_stack_items(&stack_items1);

out:
	printf("\n\n");

	return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	enum rec_type type = *(enum rec_type *)data;

	switch (type) {
	case REC_CALL_STACK:
		return handle_call_stack(ctx, data);
	case REC_FUNC_TRACE_START:
		return handle_func_trace_start(ctx, data);
	case REC_FUNC_TRACE_ENTRY:
	case REC_FUNC_TRACE_EXIT:
		return handle_func_trace_entry(ctx, data);
	default:
		fprintf(stderr, "Unrecognized record type %d\n", type);
		return -ENOTSUP;
	}
}

static void handle_event_pb(void *ctx, int cpu, void *data, unsigned data_sz)
{
	(void)handle_event(ctx, data, data_sz);
}

static int func_flags(const char *func_name, const struct btf *btf, int btf_id)
{
	const struct btf_type *t;

	if (!btf_id) {
		/* for kprobes-only functions we might not have BTF info,
		 * so assume int-returning failing function as the most common
		 * case
		 */
		return FUNC_NEEDS_SIGN_EXT;
	}

	/* FUNC */
	t = btf__type_by_id(btf, btf_id);

	/* FUNC_PROTO */
	t = btf__type_by_id(btf, t->type);

	/* check FUNC_PROTO's return type for VOID */
	if (!t->type)
		return FUNC_CANT_FAIL | FUNC_RET_VOID;

	t = btf__type_by_id(btf, t->type);
	while (btf_is_mod(t) || btf_is_typedef(t))
		t = btf__type_by_id(btf, t->type);

	if (btf_is_ptr(t))
		return FUNC_RET_PTR; /* can fail, no sign extension */

	/* unsigned is treated as non-failing */
	if (btf_is_int(t)) {
		if (btf_int_encoding(t) & BTF_INT_BOOL)
			return FUNC_CANT_FAIL | FUNC_RET_BOOL;
		if (!(btf_int_encoding(t) & BTF_INT_SIGNED))
			return FUNC_CANT_FAIL;
	}

	/* byte and word are treated as non-failing */
	if (t->size < 4)
		return FUNC_CANT_FAIL;

	/* integers need sign extension */
	if (t->size == 4)
		return FUNC_NEEDS_SIGN_EXT;

	return 0;
}

static bool func_filter(const struct mass_attacher *att,
			const struct btf *btf, int func_btf_id,
			const char *name, int func_id)
{
	/* no extra filtering for now */
	return true;
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

#define INTEL_FIXED_VLBR_EVENT        0x1b00

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
}

int main(int argc, char **argv, char **envp)
{
	long page_size = sysconf(_SC_PAGESIZE);
	struct mass_attacher_opts att_opts = {};
	const struct btf *vmlinux_btf = NULL;
	struct ksyms *ksyms = NULL;
	struct mass_attacher *att = NULL;
	struct retsnoop_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	struct perf_buffer *pb = NULL;
	int *lbr_perf_fds = NULL;
	char vmlinux_path[1024] = {};
	const struct ksym *stext_sym = 0;
	int err, i, j, n;
	size_t tmp_n;
	__u64 ts1, ts2;

	if (setvbuf(stdout, NULL, _IOLBF, BUFSIZ))
		fprintf(stderr, "Failed to set output mode to line-buffered!\n");

	/* set allowed error mask to all 1s (enabled by default) */
	memset(env.allow_error_mask, 0xFF, sizeof(env.allow_error_mask));

	memset(underline, '-', sizeof(underline) - 1);
	memset(spaces, ' ', sizeof(spaces) - 1);

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
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

	/* Open BPF skeleton */
	env.ctx.skel = skel = retsnoop_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton.\n");
		err = -EINVAL;
		goto cleanup_silent;
	}

	bpf_map__set_max_entries(skel->maps.stacks, env.stacks_map_sz);

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
	skel->rodata->verbose = env.bpf_logs;
	skel->rodata->extra_verbose = env.debug_extra;
	skel->rodata->targ_tgid = env.pid;
	skel->rodata->emit_success_stacks = env.emit_success_stacks;
	skel->rodata->emit_intermediate_stacks = env.emit_intermediate_stacks;
	skel->rodata->duration_ns = env.longer_than_ms * 1000000ULL;

	memset(skel->rodata->spaces, ' ', sizeof(skel->rodata->spaces) - 1);

	skel->rodata->use_ringbuf = env.has_ringbuf;
	if (env.has_ringbuf) {
		bpf_map__set_type(skel->maps.rb, BPF_MAP_TYPE_RINGBUF);
		bpf_map__set_key_size(skel->maps.rb, 0);
		bpf_map__set_value_size(skel->maps.rb, 0);
		bpf_map__set_max_entries(skel->maps.rb, env.ringbuf_sz);
	} else {
		bpf_map__set_type(skel->maps.rb, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
		bpf_map__set_key_size(skel->maps.rb, 4);
		bpf_map__set_value_size(skel->maps.rb, 4);
		bpf_map__set_max_entries(skel->maps.rb, 0);
	}

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

	if (env.emit_func_trace) {
		skel->rodata->emit_func_trace = true;

		err = init_func_traces();
		if (err) {
			fprintf(stderr, "Failed to initialize func traces state: %d\n", err);
			goto cleanup;
		}
	}

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
	att_opts.func_filter = func_filter;
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

	vmlinux_btf = mass_attacher__btf(att);
	for (i = 0; i < n; i++) {
		const struct mass_attacher_func_info *finfo;
		const struct glob *glob;
		struct func_info *fi;
		__u32 flags;

		finfo = mass_attacher__func(att, i);
		flags = func_flags(finfo->name, vmlinux_btf, finfo->btf_id);

		for (j = 0; j < env.entry_glob_cnt; j++) {
			glob = &env.entry_globs[j];
			if (!full_glob_matches(glob->name, glob->mod, finfo->name, finfo->module))
				continue;

			flags |= FUNC_IS_ENTRY;

			if (env.verbose)
				printf("Function '%s' is marked as an entry point.\n", finfo->name);

			break;
		}

		fi = (struct func_info *)func_info(&env.ctx, i);
		strncpy(fi->name, finfo->name, MAX_FUNC_NAME_LEN - 1);
		fi->name[MAX_FUNC_NAME_LEN - 1] = '\0';
		fi->ip = finfo->addr;
		fi->flags = flags;
	}

	for (i = 0; i < env.entry_glob_cnt; i++) {
		const struct glob *glob = &env.entry_globs[i];
		bool matched = false;

		for (j = 0, n = mass_attacher__func_cnt(att); j < n; j++) {
			const struct mass_attacher_func_info *finfo = mass_attacher__func(att, j);

			if (full_glob_matches(glob->name, glob->mod, finfo->name, finfo->module)) {
				matched = true;
				break;
			}
		}

		if (!matched && glob->mandatory) {
			err = -ENOENT;
			if (glob->mod) {
				fprintf(stderr, "Entry glob '%s[%s]' doesn't match any kernel function!\n",
					glob->name, glob->mod);
			} else {
				fprintf(stderr, "Entry glob '%s' doesn't match any kernel function!\n",
					glob->name);
			}
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

	signal(SIGINT, sig_handler);

	env.ctx.att = att;
	env.ctx.ksyms = ksyms__load();
	if (!env.ctx.ksyms) {
		fprintf(stderr, "Failed to load /proc/kallsyms for symbolization.\n");
		goto cleanup;
	}

	/* Set up ring/perf buffer polling */
	if (env.has_ringbuf) {
		rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, &env.ctx, NULL);
		if (!rb) {
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto cleanup;
		}
	} else {
		pb = perf_buffer__new(bpf_map__fd(skel->maps.rb),
				      env.perfbuf_percpu_sz / page_size,
				      handle_event_pb, NULL, &env.ctx, NULL);
		err = libbpf_get_error(pb);
		if (err) {
			fprintf(stderr, "Failed to create perf buffer: %d\n", err);
			goto cleanup;
		}
	}

	/* Allow mass tracing */
	mass_attacher__activate(att);

	/* Process events */
	if (env.bpf_logs)
		printf("BPF-side logging is enabled. Use `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see logs.\n");
	printf("Receiving data...\n");
	while (!exiting) {
		err = rb ? ring_buffer__poll(rb, 100) : perf_buffer__poll(pb, 100);
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

	free_func_traces();

	free(stack_items1.items);
	free(stack_items2.items);

	if (err == 0) {
		ts2 = now_ns();
		printf("DONE in %ld ms.\n", (long)((ts2 - ts1) / 1000000));
	}

	return -err;
}
