/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2024 Meta Platforms, Inc. */
#ifndef __LOGIC_H
#define __LOGIC_H

#include <stdint.h>
#include "utils.h"
#include "env.h"
#include <linux/perf_event.h>
#include "retsnoop.h"

struct func_args_item {
	int func_id;
	int seq_id;
	short data_len;
	short arg_ptrs;
	short arg_lens[MAX_FNARGS_ARG_SPEC_CNT];
	char *arg_data;
};

struct ctx_capture_item {
	int probe_id;
	int seq_id;
	short data_len;
	char *data;
};

enum trace_item_kind {
	TRACE_ITEM_FUNC,
	TRACE_ITEM_PROBE,
};

struct trace_item {
	enum trace_item_kind kind;
	int id; /* func ID or probe ID */
	long ts;
	int seq_id;
	int depth; /* 1-based, negative means exit from function */
	long func_res;
	long func_lat;
	union {
		const struct func_args_item *fai;
		const struct ctx_capture_item *cci;
	};
};

struct session {
	int pid;
	int tgid;
	uint64_t start_ts;
	char proc_comm[16];
	char task_comm[16];

	int lbrs_sz;
	int ft_cnt;
	int fn_args_cnt;
	int ctx_cnt;

	struct perf_branch_entry *lbrs;
	struct trace_item *trace_entries;
	struct func_args_item *fn_args_entries;
	struct ctx_capture_item *ctx_entries;
};

struct func_arg_spec {
	const char *name;
	int btf_id, pointee_btf_id;
	enum func_arg_flags arg_flags;
};

struct func_args_info {
	struct func_arg_spec arg_specs[MAX_FNARGS_ARG_SPEC_CNT];
	int arg_spec_cnt;
	const struct btf *btf; /* WARNING: references mass_attacher's BTFs */
};

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

	void *extra;
};

const struct func_info *func_info(const struct ctx *ctx, __u32 id);

enum func_flags;

int func_flags(const char *func_name, const struct btf *btf, int btf_id);
void format_func_flags(char *buf, size_t buf_sz, enum func_flags flags);

int handle_event(void *ctx, void *data, size_t data_sz);

long read_dropped_sessions(void);

/*
 * Function args capture
 */

const struct func_args_info *func_args_info(int func_id);

struct mass_attacher_func_info;
int prepare_fn_args_specs(int func_idx, const struct mass_attacher_func_info *finfo);

struct func_args_capture;
int handle_func_args_capture(struct ctx *ctx, struct session *sess,
			     const struct func_args_capture *r);
int handle_ctx_capture(struct ctx *ctx, struct session *sess, const struct ctx_capture *r);

void emit_fnargs_data(FILE *f, struct stack_item *s,
		      const struct func_args_info *fn_args,
		      const struct func_args_item *fai,
		      int indent_shift);

struct inj_probe_info;
void emit_ctx_data(FILE *f, struct stack_item *s, int indent_shift,
		   const struct inj_probe_info *inj,
		   const struct ctx_capture_item *cci);

#endif /* __LOGIC_H */
