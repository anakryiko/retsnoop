// SPDX-License-Identifier: BSD-2-Clause
#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "BSD";

int my_var = 0;

SEC("kprobe")
int simple_prog(struct pt_regs *ctx)
{
	my_var++;
	return 0;
}
