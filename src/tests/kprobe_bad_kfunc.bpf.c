// SPDX-License-Identifier: BSD-2-Clause
#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "BSD";

SEC("kprobe/non-existing-kprobe")
int kprobe(struct pt_regs *ctx)
{
	return 0;
}
