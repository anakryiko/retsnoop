/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2021 Facebook */
#ifndef __RETSNOOP_H
#define __RETSNOOP_H

/* MAX_FUNC_CNT needs to be power-of-2 */
#define MAX_FUNC_CNT (4 * 1024)
#define MAX_FUNC_MASK (MAX_FUNC_CNT - 1)
#define MAX_FUNC_NAME_LEN 40

#define MAX_FSTACK_DEPTH 64
#define MAX_KSTACK_DEPTH 128

#define MAX_LBR_ENTRIES 32

struct perf_branch_entry1 {
	__u64	from;
	__u64	to;
	__u64	mispred:1,  /* target mispredicted */
		predicted:1,/* target predicted */
		in_tx:1,    /* in transaction */
		abort:1,    /* transaction abort */
		cycles:16,  /* cycle count to last branch */
		type:4,     /* branch type */
		reserved:40;
};

struct call_stack {
	unsigned short func_ids[MAX_FSTACK_DEPTH];
	long func_res[MAX_FSTACK_DEPTH];
	long func_lat[MAX_FSTACK_DEPTH];
	unsigned depth;
	unsigned max_depth;
	int pid;
	long emit_ts;
	char comm[16];
	bool is_err;

	unsigned short saved_ids[MAX_FSTACK_DEPTH];
	long saved_res[MAX_FSTACK_DEPTH];
	long saved_lat[MAX_FSTACK_DEPTH];
	unsigned saved_depth;
	unsigned saved_max_depth;

	long kstack[MAX_KSTACK_DEPTH];
	long kstack_sz;

	struct perf_branch_entry1 lbr_entries[MAX_LBR_ENTRIES];
	int lbr_entry_cnt;
};

#define FUNC_IS_ENTRY 0x1
#define FUNC_CANT_FAIL 0x2
#define FUNC_NEEDS_SIGN_EXT 0x4
#define FUNC_RET_PTR 0x8
#define FUNC_RET_BOOL 0x10
#define FUNC_RET_VOID 0x20

#define TASK_COMM_LEN 16

#endif /* __RETSNOOP_H */
