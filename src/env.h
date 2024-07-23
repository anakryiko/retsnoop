/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2024 Meta Platforms, Inc. */
#ifndef __ENV_H
#define __ENV_H

#include "utils.h"

struct mass_attacher;
struct retsnoop_bpf;
struct ksyms;
struct addr2line;

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

enum args_fmt_mode {
	/* (default) compact, all args in single line */
	ARGS_FMT_COMPACT = 0,
	/* one arg per line, entire arg is still on the single line */
	ARGS_FMT_MULTILINE = 1,
	/* multi-line, each arg starts on new line, but takes as many lines as necessary to render */
	ARGS_FMT_VERBOSE = 2,
};

enum debug_feat {
	DEBUG_NONE = 0x00,
	DEBUG_MULTI_KPROBE = 0x01,
	DEBUG_FULL_LBR = 0x02,
	DEBUG_BPF = 0x04,
};

struct env {
	bool show_version;
	bool show_config_help;
	bool verbose;
	bool debug;
	bool debug_extra;
	bool dry_run;
	bool emit_success_stacks;
	bool emit_func_trace;
	bool capture_args;
	enum attach_mode attach_mode;
	enum debug_feat debug_feats;
	bool use_lbr;
	long lbr_flags;
	int lbr_max_cnt;
	const char *vmlinux_path;
	int pid;
	int longer_than_ms;

	/* Stack symbolization settings */
	enum symb_mode symb_mode;
	bool stack_emit_all;
	bool stack_emit_addrs;
	bool stack_dec_offs;

	/* Args capture settings */
	int args_max_total_args_size;
	int args_max_sized_arg_size;
	int args_max_str_arg_size;
	enum args_fmt_mode args_fmt_mode;
	int args_fmt_max_arg_width;

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
	uint64_t allow_error_mask[(MAX_ERRNO + 1) / 64];
	uint64_t deny_error_mask[(MAX_ERRNO + 1) / 64];

	struct ctx ctx;
	int ringbuf_map_sz;
	int sessions_map_sz;

	int cpu_cnt;
	bool has_branch_snapshot;
	bool has_lbr;
	bool has_ringbuf;
};

extern struct env env;
extern const struct argp argp;

void print_config_help_message(void);

#endif /* __ENV_H */
