// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2024 Meta Platforms, Inc. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

long addr;
long value;
int read_err;

SEC("raw_tp")
int kmem_read(void *ctx)
{
	read_err = bpf_probe_read_kernel(&value, 8, (void *)addr);
	return 0;
}
