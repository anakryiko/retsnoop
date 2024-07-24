// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2024 Meta Platforms, Inc. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <argp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/perf_event.h>
#include "env.h"
#include "retsnoop.h"

#define DEFAULT_RINGBUF_SZ 8 * 1024 * 1024
#define DEFAULT_SESSIONS_SZ 4096
#define DEFAULT_FNARGS_FMT_MAX_ARG_WIDTH 120

const char *argp_program_version = "retsnoop v0.9.8";
const char *argp_program_bug_address = "Andrii Nakryiko <andrii@kernel.org>";
const char argp_program_doc[] =
"retsnoop tool shows kernel call stacks based on specified function filters.\n"
"\n"
"USAGE: retsnoop [-v] [-B] [-T] [-A] [-e GLOB]* [-a GLOB]* [-d GLOB]*\n";

struct env env = {
	.ringbuf_map_sz = DEFAULT_RINGBUF_SZ,
	.sessions_map_sz = DEFAULT_SESSIONS_SZ,
	.args_max_total_args_size = DEFAULT_FNARGS_TOTAL_ARGS_SZ,
	.args_max_sized_arg_size = DEFAULT_FNARGS_SIZED_ARG_SZ,
	.args_max_str_arg_size = DEFAULT_FNARGS_STR_ARG_SZ,
	.args_fmt_max_arg_width = DEFAULT_FNARGS_FMT_MAX_ARG_WIDTH,
};

__attribute__((constructor))
static void env_init()
{
	/* set allowed error mask to all 1s (enabled by default) */
	memset(env.allow_error_mask, 0xFF, sizeof(env.allow_error_mask));
}
struct cfg_spec;

typedef int (*cfg_parse_fn)(const struct cfg_spec *cfg, const char *arg, void *dst, void *ctx);

struct cfg_spec {
	const char *group;
	const char *key;
	cfg_parse_fn parse_fn;
	void *dst; /* value to set */
	void *ctx; /* additional parser context, e.g., integer limits */
	const char *short_help;
	const char *help;
};

struct int_lims { int min_val, max_val; };

struct enum_mapping { const char *name; char alias; int value; };

static int cfg_bool(const struct cfg_spec *cfg, const char *arg, void *dst, void *ctx);
static int cfg_int(const struct cfg_spec *cfg, const char *arg, void *dst, void *ctx);
static int cfg_enum(const struct cfg_spec *cfg, const char *arg, void *dst, void *ctx);

#define OPT_STACKS_MAP_SIZE 1002
#define OPT_DRY_RUN 1004
#define OPT_DEBUG_FEAT 1005
#define OPT_RINGBUF_MAP_SIZE 1006
#define OPT_CONFIG_HELP 1007

static const struct argp_option opts[] = {
	 /* Target functions specification */
	{ .flags = OPTION_DOC, "TARGETING\n=========================" },
	{ "case", 'c', "CASE", 0,
	  "Use a pre-defined set of entry/allow/deny globs for a given use case (supported cases: bpf, perf)" },
	{ "entry", 'e', "GLOB", 0,
	  "Glob for entry functions that trigger error stack trace collection" },
	{ "allow", 'a', "GLOB", 0,
	  "Glob for allowed functions captured in error stack trace collection" },
	{ "deny", 'd', "GLOB", 0,
	  "Glob for denied functions ignored during error stack trace collection" },

	/* Running mode configuration */
	{ .flags = OPTION_DOC, "RUNMODE\n=========================" },
	{ "trace", 'T', NULL, 0, "Capture and emit function call traces" },
	{ "capture-args", 'A', NULL, 0, "Capture and emit function arguments" },
	{ "lbr", 'B', "SPEC", OPTION_ARG_OPTIONAL,
	  "Capture and print LBR (Last Branch Record) entries (defaults to any_return). "
	  "Exact set of captured LBR records can be specified using "
	  "raw LBR flags value (hex or decimal) or through symbolic aliases: "
	  "any_return (default), any, any_call, cond, call, ind_call, ind_jump, "
	  "call_stack, abort_tx, in_tx, no_tx. "
	  "You can combine multiple of them by using --lbr argument multiple times. "
	  "See perf_branch_sample_type in perf_event UAPI (include/uapi/linux/perf_event.h)" },
	{ "dry-run", OPT_DRY_RUN, NULL, 0,
	  "Perform a dry run: don't actually load and attach BPF programs, but report all the steps and data" },
	/* Attach mechanism specification */
	{ "kprobes-multi", 'M', NULL, 0,
	  "Use multi-attach kprobes/kretprobes, if supported; fall back to single-attach kprobes/kretprobes, otherwise" },
	{ "kprobes", 'K', NULL, 0, "Use single-attach kprobes/kretprobes" },
	{ "fentries", 'F', NULL, 0, "Use fentries/fexits instead of kprobes/kretprobes" },

	/* Stack filtering specification */
	{ .flags = OPTION_DOC, "FILTERING\n=========================" },
	{ "pid", 'p', "PID", 0,
	  "Only trace given PID" },
	{ "no-pid", 'P', "PID", 0,
	  "Skip tracing given PID" },
	{ "comm", 'n', "NAME", 0,
	  "Only trace processes with given name" },
	{ "no-comm", 'N', "NAME", 0,
	  "Skip tracing processes with given name" },
	{ "longer", 'L', "MS", 0,
	  "Only emit stacks that took at least a given amount of milliseconds" },
	{ "success-stacks", 'S', NULL, 0, "Emit any stack, successful or not" },
	{ "allow-errors", 'x', "ERROR", 0, "Record stacks only with specified errors" },
	{ "deny-errors", 'X', "ERROR", 0, "Ignore stacks that have specified errors" },

	/* Misc more rarely used/advanced settings */
	{ .flags = OPTION_DOC, "ADVANCED\n=========================" },
	{ "kernel", 'k', "PATH", 0, "Path to vmlinux image with DWARF information embedded" },
	{ "symbolize", 's', "LEVEL", OPTION_ARG_OPTIONAL,
	  "Set stack symbolization mode:\n"
	  "\t-s for line info,\n"
	  "\t-ss for also inline functions,\n"
	  "\t-sn to disable extra symbolization.\n"
	  "If extra symbolization is requested, retsnoop relies on having\n"
	  "vmlinux with DWARF available" },
	{ "debug", OPT_DEBUG_FEAT, "FEATURE", 0,
	  "Enable selected debug features.\nSupported: multi-kprobe, full-lbr, bpf" },

	/* Extra config settings */
	{ .flags = OPTION_DOC, "EXTRA CONFIGURATION\n=========================" },
	{ "config", 'C', "CONFIG", 0, "Specify extra configuration parameters:" },
	{ "config-help", OPT_CONFIG_HELP, NULL, 0, "Output support full config parameters help" },

	/* Help, version, logging, dry-run, etc */
	{ .flags = OPTION_DOC, "USAGE, HELP, VERSION\n=========================" },
	{ "help", 'h', NULL, 0, "Show the full help" },
	{ "verbose", 'v', NULL, 0,
	  "Verbose output (use -vv for debug-level verbosity, -vvv for extra debug log)" },
	{ "version", 'V', NULL, 0,
	  "Print out retsnoop version" },
	{},
};

static struct cfg_spec cfg_specs[] = {
	/* BPF maps/data sizing */
	{ "bpf", "ringbuf-size", cfg_int, &env.ringbuf_map_sz, NULL,
	  "BPF ringbuf size (defaults to 8MB)",
	  "BPF ringbuf size in bytes.\n"
	   "\tIncrease if you experience dropped data. By default is set to 8MB." },
	{ "bpf", "sessions-size", cfg_int, &env.sessions_map_sz, NULL,
	  "BPF sessions map capacity (defaults to 4096)" },

	/* Stack trace formatting */
	{ "fmt", "stack-trace-mode", cfg_enum, &env.symb_mode,
	  (struct enum_mapping[]){
		  {"linenum", 'l', SYMB_LINEINFO},
		  {"inlines", 'i', SYMB_INLINES},
		  {"none", 'n', SYMB_NONE},
		  {},
	  },
	  "Stack symbolization mode",
	  "Stack symbolization mode.\n"
	  "\tDetermines how much processing is done for stack symbolization\n"
	  "\tand what kind of extra information is included in stack traces:\n"
	  "\t    none    - no source code info, no inline functions;\n"
	  "\t    linenum - source code info (file:line), no inline functions;\n"
	  "\t    inlines - source code info and inline functions." },
	{ "fmt", "stack-emit-all", cfg_bool, &env.stack_emit_all, NULL,
	  "Emit all stack stace/LBR entries (turning off relevancy filtering)" },
	{ "fmt", "stack-emit-addrs", cfg_bool, &env.stack_emit_addrs, NULL,
	  "Emit raw captured stack trace/LBR addresses (in addition to symbols)" },
	{ "fmt", "stack-dec-offs", cfg_bool, &env.stack_dec_offs, NULL,
	  "Emit stack trace/LBR function offsets in decimal (by default, it's in hex)" },

	/* Function args formatting */
	{ "args", "max-total-args-size",
	  cfg_int, &env.args_max_total_args_size, &(struct int_lims){1, MAX_FNARGS_TOTAL_ARGS_SZ},
	  "Maximum total amount of data (in bytes) captured for all args of any function call" },
	{ "args", "max-sized-arg-size",
	  cfg_int, &env.args_max_sized_arg_size, &(struct int_lims){1, MAX_FNARGS_SIZED_ARG_SZ},
	  "Maximum amount of data (in bytes) captured for any fixed-sized (int, struct, etc) function argument" },
	{ "args", "max-str-arg-size",
	  cfg_int, &env.args_max_str_arg_size, &(struct int_lims){1, MAX_FNARGS_STR_ARG_SZ},
	  "Maximum amount of data (in bytes) captured for any string function argument" },
	{ "args", "fmt-mode", cfg_enum, &env.args_fmt_mode,
	  (struct enum_mapping[]){
		  {"compact", 'c', ARGS_FMT_COMPACT},
		  {"multiline", 'm', ARGS_FMT_MULTILINE},
		  {"verbose", 'v', ARGS_FMT_VERBOSE},
		  {},
	  },
	  "Function arguments formatting mode (compact, multiline, verbose)" },
	{ "args", "fmt-max-arg-width", cfg_int, &env.args_fmt_max_arg_width, &(struct int_lims){0, 250},
	  "Maximum amount of horizontal space taken by a single argument output.\n"
	  "Applies only to compact and multiline modes. If set to zero, no truncation is performed." },

	/* LBR formatting */
	{ "fmt", "lbr-max-count", cfg_int, &env.lbr_max_cnt, NULL,
	  "Limit number of printed LBRs to N" },
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
		{"bpf", DEBUG_BPF},
	};

	for (i = 0; i < ARRAY_SIZE(table); i++) {
		if (strcmp(table[i].alias, arg) == 0) {
			env.debug_feats |= table[i].value;
			return 0;
		}
	}

	return -EINVAL;
}

static enum debug_feat parse_config_arg(const char *arg)
{
	const char *g, *k, *v;
	int grp_len, key_len;
	int i;

	g = arg;
	k = strchr(arg, '.');
	if (!k) {
		elog("Invalid configuration value '%s', expected format is 'group.key=value'\n", arg);
		return -EINVAL;
	}
	k++;
	v = strchr(arg, '=');
	if (!v) {
		elog("Invalid configuration value '%s', expected format is 'group.key=value'\n", arg);
		return -EINVAL;
	}
	v++;

	grp_len = k - g - 1;
	key_len = v - k - 1;

	for (i = 0; i < ARRAY_SIZE(cfg_specs); i++) {
		struct cfg_spec *cfg = &cfg_specs[i];

		if (strncmp(cfg->group, g, grp_len) != 0 || cfg->group[grp_len] != '\0' ||
		    strncmp(cfg->key, k, key_len) != 0 || cfg->key[key_len] != '\0')
			continue;

		return cfg->parse_fn(cfg, v, cfg->dst, cfg->ctx);
	}

	elog("Config '%.*s.%.*s' unrecognized!\n", grp_len, g, key_len, k);

	return -ESRCH;
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
		if (!env.verbose)
			env.verbose = true;
		else if (!env.debug)
			env.debug = true;
		else if (!env.debug_extra)
			env.debug_extra = true;
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
	case 'L':
		errno = 0;
		env.longer_than_ms = strtol(arg, NULL, 10);
		if (errno || env.longer_than_ms <= 0) {
			fprintf(stderr, "Invalid -L duration: %d\n", env.longer_than_ms);
			return -EINVAL;
		}
		break;
	case 'B':
		env.use_lbr = true;
		if (arg && parse_lbr_arg(arg))
			return -EINVAL;
		break;
	case 'A':
		env.capture_args = true;
		break;
	case OPT_STACKS_MAP_SIZE:
		errno = 0;
		env.sessions_map_sz = strtol(arg, NULL, 10);
		if (errno || env.sessions_map_sz < 0) {
			fprintf(stderr, "Invalid sessions map size: %d\n", env.sessions_map_sz);
			return -EINVAL;
		}
		break;
	case OPT_RINGBUF_MAP_SIZE:
		errno = 0;
		env.ringbuf_map_sz = strtol(arg, NULL, 10);
		if (errno || env.ringbuf_map_sz < 0) {
			fprintf(stderr, "Invalid ringbuf map size: %d\n", env.ringbuf_map_sz);
			return -EINVAL;
		}
		break;
	case OPT_DRY_RUN:
		env.dry_run = true;
		break;
	case 'C':
		if (parse_config_arg(arg))
			return -EINVAL;
		break;
	case OPT_CONFIG_HELP:
		env.show_config_help = true;
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

static int cfg_int(const struct cfg_spec *cfg, const char *arg, void *dst, void *ctx)
{
	int *val = dst;
	struct int_lims *lims = ctx;
	int min_val = lims ? lims->min_val : 1;
	int max_val = lims ? lims->max_val : INT_MAX;

	errno = 0;
	*val = strtol(arg, NULL, 10);
	if (errno || *val < min_val || *val > max_val) {
		fprintf(stderr, "Invalid '%s.%s' config value '%s'. Expected valid integer in [%d, %d] range.\n",
			cfg->group, cfg->key, arg, min_val, max_val);
		return -EINVAL;
	}

	return 0;
}

static int cfg_bool(const struct cfg_spec *cfg, const char *arg, void *dst, void *ctx)
{
	bool *val = dst;

	if (strcasecmp(arg, "true") == 0 || strcmp(arg, "1") == 0) {
		*val = true;
	} else if (strcasecmp(arg, "false") == 0 || strcmp(arg, "0") == 0) {
		*val = false;
	} else {
		elog("Invalid '%s.%s' config value '%s'. Expected to be 'true' or '1' for enabling the option; 'false' or '0' for disabling it.\n",
		     cfg->group, cfg->key, arg);
		return -EINVAL;
	}

	return 0;
}

static int cfg_enum(const struct cfg_spec *cfg, const char *arg, void *dst, void *ctx)
{
	int *val = dst;
	struct enum_mapping *mapping = ctx, *m;

	m = mapping;
	while (m->name) {
		if (strcasecmp(arg, m->name) == 0) {
			*val = m->value;
			return 0;
		}
		if (m->alias && arg[0] == m->alias && arg[1] == '\0') {
			*val = m->value;
			return 0;
		}
		m++;
	}

	elog("Invalid '%s.%s' config value '%s'. Expected one of:", cfg->group, cfg->key, arg);
	m = mapping;
	while (m->name) {
		elog("%s '%s'", m == mapping ? "" : ",", m->name);
		m++;
	}
	elog(".\n");

	return -EINVAL;
}

void print_config_help_message(void)
{
	int i;

	log("It's possible to customize various retsnoop's internal implementation details.\n");
	log("This can be done by specifying one or multiple extra parameters using --config KEY=VALUE CLI arguments.\n\n");

	log("Supported configuration parameters:\n");
	for (i = 0; i < ARRAY_SIZE(cfg_specs); i++) {
		log("  %s.%s - %s\n",
		    cfg_specs[i].group, cfg_specs[i].key,
		    cfg_specs[i].help ?: cfg_specs[i].short_help);
	}
}

static char *help_filter(int key, const char *text, void *input)
{
	if (key == 'C') {
		char *msg = NULL;
		FILE *f;
		size_t msg_sz, i;

		f = open_memstream(&msg, &msg_sz);
		if (!f)
			return (char *)text;

		fprintf(f, "%s", text);
		for (i = 0; i < ARRAY_SIZE(cfg_specs); i++) {
			fprintf(f, "\n%s.%s - %s",
				cfg_specs[i].group, cfg_specs[i].key, cfg_specs[i].short_help);
		}
		fclose(f);
		return msg;
	}
	return (char *)text;
}

const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
	.help_filter = help_filter,
};

