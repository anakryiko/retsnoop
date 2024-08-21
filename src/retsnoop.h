/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2021 Facebook */
#ifndef __RETSNOOP_H
#define __RETSNOOP_H

#define MAX_FUNC_NAME_LEN 40

#define MAX_FSTACK_DEPTH 64
#define MAX_KSTACK_DEPTH 128

#define MAX_LBR_ENTRIES 32

/* Linux allows error from -1 up to -4095, even though most of the values are
 * not used
 */
#define MAX_ERR_CNT 4096

#define TASK_COMM_LEN 16

struct stats {
	long dropped_sessions;
	long incomplete_sessions;
};
enum rec_type {
	REC_SESSION_START,
	REC_FUNC_TRACE_ENTRY,
	REC_FUNC_TRACE_EXIT,
	REC_FNARGS_CAPTURE,
	REC_CTXARGS_CAPTURE,
	REC_LBR_STACK,
	REC_INJ_PROBE,
	REC_SESSION_END,
};

enum func_flags {
	FUNC_IS_ENTRY = 0x1,
	FUNC_CANT_FAIL = 0x2,
	FUNC_NEEDS_SIGN_EXT = 0x4,
	FUNC_RET_PTR = 0x8,
	FUNC_RET_BOOL = 0x10,
	FUNC_RET_VOID = 0x20,
};

#define MAX_FNARGS_ARG_SPEC_CNT 12
#define MAX_FNARGS_TOTAL_ARGS_SZ (64 * 1024)	/* maximum total captured args data size */
#define MAX_FNARGS_SIZED_ARG_SZ (16 * 1024)	/* maximum capture size for a single fixed-sized arg */
#define MAX_FNARGS_STR_ARG_SZ (16 * 1024)	/* maximum capture size for a signel string arg */

#define DEFAULT_FNARGS_TOTAL_ARGS_SZ 3072	/* default total captured args data size */
#define DEFAULT_FNARGS_SIZED_ARG_SZ 256		/* default capture size for a single fixed-sized arg */
#define DEFAULT_FNARGS_STR_ARG_SZ 256		/* default capture size for a signel string arg */

/* should fit inside FNARGS_LOC_MASK */
enum func_arg_loc {
	FNARGS_SKIP = 0,
	FNARGS_REG = 1,
	FNARGS_REG_PAIR = 2,
	FNARGS_STACK = 3,
};

/* should fit inside FNARGS_KIND_MASK */
enum func_arg_kind {
	FNARGS_KIND_RAW = 0,
	FNARGS_KIND_PTR = 1,
	FNARGS_KIND_STR = 2,
	FNARGS_KIND_VARARG = 3,
};

enum func_arg_flags {
	/* lowest 16 bits specify amount of data to be captured */
	FNARGS_LEN_MASK = 0xffff,	/* 64KB bytes max */

	/* next 2 bits specify location of argument (register, stack, register pair, skipped) */
	FNARGS_LOC_MASK = 0x30000,	/* enum func_arg_loc */
	FNARGS_LOC_SHIFT = 16,

	/* next 2 bits specify extra semantics of the argument (pointer, string, vararg) */
	FNARGS_KIND_MASK = 0xc0000,	/* enum func_arg_kind */
	FNARGS_KIND_SHIFT = 18,

	/* for REG_PAIR/REG we encode the first/only argument register index */
	FNARGS_REGIDX_MASK = 0x0ff00000,	/* argument register index */
	FNARGS_REGIDX_SHIFT = 20,

	/* for STACK we have one big offset */
	FNARGS_STACKOFF_MASK = 0xfff00000,	/* stack offset */
	FNARGS_STACKOFF_SHIFT = 20,
	FNARGS_STACKOFF_MAX = 8 * (FNARGS_STACKOFF_MASK >> FNARGS_STACKOFF_SHIFT),

	/* special "skip arg" values, uses special REGIDX value */
	FNARGS_UNKN			= 0x0fe00000,
	FNARGS_UNKN_VARARG		= 0x0fd00000,
	FNARGS_STACKOFF_2BIG		= 0x0fc00000,
};

struct func_info {
	char name[MAX_FUNC_NAME_LEN];
	__u64 ip;
	enum func_flags flags;
	/* set of enum func_arg_flags + capture length */
	unsigned arg_specs[MAX_FNARGS_ARG_SPEC_CNT];
} __attribute__((aligned(8)));

#define MAX_CTXARGS_SPEC_CNT 12

enum ctxarg_kind {
	CTXARG_KIND_VALUE,
	CTXARG_KIND_PTR_FIXED,
	CTXARG_KIND_PTR_STR,
	CTXARG_KIND_TP_STR,
};

enum ctxarg_flags {
	/* lowest 16 bits specify the amount of data to be captured */
	CTXARG_LEN_MASK = 0xffff,

	/* next 8 bits specify offset to read from (relative to context) */
	CTXARG_OFF_MASK = 0xff0000,
	CTXARG_OFF_SHIFT = 16,

	/* next 2 bits specify the kind of context argument */
	CTXARG_KIND_MASK = 0x3000000,
	CTXARG_KIND_SHIFT = 24,
};

struct ctxargs_info {
	unsigned specs[MAX_CTXARGS_SPEC_CNT];
} __attribute__((aligned(8)));

struct rec_session_start {
	/* REC_SESSION_START */
	enum rec_type type;
	int pid;
	int tgid;
	long start_ts;
	char task_comm[16], proc_comm[16];
};

struct rec_func_trace_entry {
	/* REC_FUNC_TRACE_ENTRY or REC_FUNC_TRACE_EXIT */
	enum rec_type type;

	int pid;
	long ts;

	int seq_id;
	short depth;
	unsigned short func_id;

	long func_lat;
	long func_res;
};

struct rec_fnargs_capture {
	/* REC_FNARGS_CAPTURE */
	enum rec_type type;
	int pid;
	int seq_id;
	unsigned short func_id;
	unsigned short data_len;
	unsigned short arg_ptrs; /* whether we put raw ptr value into arg_data */
	short arg_lens[MAX_FNARGS_ARG_SPEC_CNT];
	char arg_data[]; /* BPF side sizes it according to settings */
};

struct rec_ctxargs_capture {
	/* REC_CTXARGS_CAPTURE */
	enum rec_type type;
	int pid;
	int seq_id;
	unsigned short probe_id;
	unsigned short data_len;
	unsigned short ptrs; /* whether we put raw ptr value into arg_data */
	short lens[MAX_CTXARGS_SPEC_CNT];
	char data[]; /* BPF side sizes it according to settings */
};

struct rec_lbr_stack {
	/* REC_LBR_STACK */
	enum rec_type type;
	int pid;

	int lbrs_sz;
	struct perf_branch_entry lbrs[MAX_LBR_ENTRIES];
};

struct rec_inj_probe {
	/* REC_INJ_PROBE */
	enum rec_type type;
	int pid;
	long ts;

	int seq_id;
	int probe_id;
	short depth;
};

/*
 * This is currently embedded inside SESSION_END record for efficiency.
 * Eventually, when stack trace is orthogonal and independent from other
 * pieces of information (LBR and function trace), this might be moved outside
 * of SESSION_END, but for now for efficiency we keep them coupled.
 */
struct call_stack {
	unsigned short func_ids[MAX_FSTACK_DEPTH];
	int seq_ids[MAX_FSTACK_DEPTH];
	long func_res[MAX_FSTACK_DEPTH];
	long func_lat[MAX_FSTACK_DEPTH];
	unsigned depth;
	unsigned max_depth;
	bool is_err;

	unsigned short saved_ids[MAX_FSTACK_DEPTH];
	int saved_seq_ids[MAX_FSTACK_DEPTH];
	long saved_res[MAX_FSTACK_DEPTH];
	long saved_lat[MAX_FSTACK_DEPTH];
	unsigned saved_depth;
	unsigned saved_max_depth;

	long kstack[MAX_KSTACK_DEPTH];
	long kstack_sz;
};

struct rec_session_end {
	/* REC_SESSION_END */
	enum rec_type type;
	int pid;
	long emit_ts;
	bool ignored;
	bool is_err;
	int last_seq_id;
	int lbrs_sz;
	int dropped_records;

	struct call_stack stack;
};

#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef ENOSPC
#define ENOSPC 28
#endif
#ifndef ENODATA
#define ENODATA 61
#endif
#ifndef ENOMSG
#define ENOMSG 42
#endif
#ifndef EDOM
#define EDOM 33
#endif

#endif /* __RETSNOOP_H */
