// SPDX-License-Identifier: BSD-2-Clause
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "BSD";

SEC("fentry/btf_struct_access")
int BPF_PROG(fentry_handler)
{
	return 0;
}
