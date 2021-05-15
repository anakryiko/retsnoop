// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_ATTEMPTS 50

int my_tid = 0;
long entry_ip = 0;
int found_off = 0;

SEC("kprobe/hrtimer_start_range_ns")
int calib_entry(struct pt_regs *ctx)
{
	pid_t tid;

	tid = (__u32)bpf_get_current_pid_tgid();
	if (tid != my_tid)
		return 0;

	entry_ip = ctx->ip - 1;

	return 0;
}

SEC("kretprobe/hrtimer_start_range_ns")
int calib_exit(struct pt_regs *ctx)
{
	struct trace_kprobe *tk;
	__u64 fp, ip, i;
	int tid, off;

	tid = (__u32)bpf_get_current_pid_tgid();
	if (tid != my_tid)
		return 0;

	/* get frame pointer */
	asm volatile ("%[fp] = r10" : [fp] "+r"(fp) :);

	for (i = 1; i <= MAX_ATTEMPTS; i++) {
		bpf_probe_read(&tk, sizeof(tk), (void *)(fp + i * sizeof(__u64)));
		ip = (__u64)BPF_CORE_READ(tk, rp.kp.addr);

		if (ip == entry_ip) {
			found_off = i;
			return 0;
		}
	}

	return 0;
}

