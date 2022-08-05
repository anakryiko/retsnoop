/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2021 Facebook */
#ifndef __RETSNOOP_H
#define __RETSNOOP_H

#define MAX_CPUS 256
#define MAX_CPUS_MSK (MAX_CPUS - 1)

/* MAX_FUNC_CNT needs to be power-of-2 */
#define MAX_FUNC_CNT (4 * 1024)
#define MAX_FUNC_MASK (MAX_FUNC_CNT - 1)
#define MAX_FUNC_NAME_LEN 40

#define MAX_FSTACK_DEPTH 64
#define MAX_KSTACK_DEPTH 128

#define MAX_LBR_ENTRIES 32

/* Linux allows error from -1 up to -4095, even though most of the values are
 * not used
 */
#define MAX_ERR_CNT 4096

struct call_stack {
	unsigned short func_ids[MAX_FSTACK_DEPTH];
	long func_res[MAX_FSTACK_DEPTH];
	long func_lat[MAX_FSTACK_DEPTH];
	unsigned depth;
	unsigned max_depth;
	int pid;
	int tgid;
	long start_ts, emit_ts;
	char task_comm[16];
	char proc_comm[16];
	bool is_err;

	unsigned short saved_ids[MAX_FSTACK_DEPTH];
	long saved_res[MAX_FSTACK_DEPTH];
	long saved_lat[MAX_FSTACK_DEPTH];
	unsigned saved_depth;
	unsigned saved_max_depth;

	long kstack[MAX_KSTACK_DEPTH];
	long kstack_sz;

	struct perf_branch_entry lbrs[MAX_LBR_ENTRIES];
	long lbrs_sz;
};

#define FUNC_IS_ENTRY 0x1
#define FUNC_CANT_FAIL 0x2
#define FUNC_NEEDS_SIGN_EXT 0x4
#define FUNC_RET_PTR 0x8
#define FUNC_RET_BOOL 0x10
#define FUNC_RET_VOID 0x20

#define TASK_COMM_LEN 16

#endif /* __RETSNOOP_H */
