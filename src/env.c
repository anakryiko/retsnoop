// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2024 Meta Platforms, Inc. */
#include <argp.h>
#include <string.h>
#include <stdlib.h>
#include <linux/perf_event.h>
#include "env.h"

const char *argp_program_version = "retsnoop v0.9.8";
const char *argp_program_bug_address = "Andrii Nakryiko <andrii@kernel.org>";
const char argp_program_doc[] =
"retsnoop tool shows kernel call stacks based on specified function filters.\n"
"\n"
"USAGE: retsnoop [-v] [-F|-K|-M] [-T] [--lbr] [-c CASE]* [-a GLOB]* [-d GLOB]* [-e GLOB]*\n";

struct env env = {
	.ringbuf_sz = 8 * 1024 * 1024,
	.perfbuf_percpu_sz = 256 * 1024,
	.stacks_map_sz = 4096,
};

__attribute__((constructor))
static void init()
{
	/* set allowed error mask to all 1s (enabled by default) */
	memset(env.allow_error_mask, 0xFF, sizeof(env.allow_error_mask));
}

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
	  "Enable selected debug features. Any set of: multi-kprobe, full-lbr." },
	{},
};

/* PRESETS */

struct preset {
	const char *name;
	const char **entry_globs;
	const char **allow_globs;
	const char **deny_globs;
};

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

static const struct preset presets[] = {
	{"bpf", bpf_entry_globs, bpf_allow_globs, bpf_deny_globs},
	{"perf", perf_entry_globs, perf_allow_globs, perf_deny_globs},
};

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
		{"full-lbr", DEBUG_FULL_LBR},
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

const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

