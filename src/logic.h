/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2024 Meta Platforms, Inc. */
#ifndef __LOGIC_H
#define __LOGIC_H

#include <stdint.h>
#include "utils.h"
#include "env.h"
#include <linux/perf_event.h>

struct func_trace_item {
	long ts;
	long func_lat;
	int func_id;
	int depth; /* 1-based, negative means exit from function */
	int seq_id;
	long func_res;
};

struct session {
	int pid;
	int tgid;
	uint64_t start_ts;
	char proc_comm[16];
	char task_comm[16];

	int lbrs_sz;
	struct perf_branch_entry *lbrs;

	int ft_cnt;
	struct func_trace_item *ft_entries;
};

const struct func_info *func_info(const struct ctx *ctx, __u32 id);

enum func_flags;

int func_flags(const char *func_name, const struct btf *btf, int btf_id);
void format_func_flags(char *buf, size_t buf_sz, enum func_flags flags);

int init_func_traces(void);

int handle_event(void *ctx, void *data, size_t data_sz);

long read_dropped_sessions(void);

#endif /* __LOGIC_H */
