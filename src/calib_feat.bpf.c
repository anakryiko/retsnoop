// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Facebook */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_ATTEMPTS 50

int my_tid = 0;
__u64 entry_ip = 0;
int kret_ip_off = 0;

bool calib_entry_happened = false;
bool calib_exit_happened = false;

bool has_bpf_get_func_ip = false;
bool has_fexit_sleep_fix = false;
bool has_fentry_protection = false;
bool has_branch_snapshot = false;
bool has_ringbuf = false;
bool has_bpf_cookie = false;
bool has_kprobe_multi = false;

SEC("ksyscall/nanosleep")
int calib_entry(struct pt_regs *ctx)
{
	pid_t tid;

	tid = (__u32)bpf_get_current_pid_tgid();
	if (tid != my_tid)
		return 0;

	calib_entry_happened = true;

	/* Used for kretprobe function entry IP discovery, before
	 * bpf_get_func_ip() helper was added.
	 */
#ifdef bpf_target_x86
	/* for x86 the IP is off by one at hardware level,
	 * see https://github.com/anakryiko/retsnoop/issues/32
	 */
	entry_ip = PT_REGS_IP(ctx) - 1;
#else
	entry_ip = PT_REGS_IP(ctx);
#endif

	/* Detect if bpf_get_func_ip() helper is supported by the kernel.
	 * Added in: 9b99edcae5c8 ("bpf: Add bpf_get_func_ip helper for tracing programs")
	 * Added in: 9ffd9f3ff719 ("bpf: Add bpf_get_func_ip helper for kprobe programs")
	 */
	has_bpf_get_func_ip = bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_func_ip);

	/* Detect if fentry/fexit re-entry protection is implemented.
	 * Added in: ca06f55b9002 ("bpf: Add per-program recursion prevention mechanism")
	 */
	has_fentry_protection = bpf_core_field_exists(struct bpf_prog, active);

	/* Detect if fexit is safe to use for long-running and sleepable
	 * kernel functions.
	 * Added in: e21aa341785c ("bpf: Fix fexit trampoline")
	 */
	has_fexit_sleep_fix = bpf_core_type_exists(struct bpf_tramp_image);

	/* Detect if bpf_get_branch_snapshot() helper is supported.
	 * Added in: 856c02dbce4f ("bpf: Introduce helper bpf_get_branch_snapshot")
	 */
	has_branch_snapshot = bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_branch_snapshot);

	/* Detect if BPF_MAP_TYPE_RINGBUF map is supported.
	 * Added in: 457f44363a88 ("bpf: Implement BPF ring buffer and verifier support for it")
	 */
	has_ringbuf = bpf_core_enum_value_exists(enum bpf_map_type, BPF_MAP_TYPE_RINGBUF);

	/* Detect if BPF cookie is supported for kprobes.
	 * Added in: 7adfc6c9b315 ("bpf: Add bpf_get_attach_cookie() BPF helper to access bpf_cookie value")
	 */
	has_bpf_cookie = bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_attach_cookie);

	/* Detect if multi-attach kprobes are supported.
	 * Added in: 0dcac2725406 ("bpf: Add multi kprobe link")
	 */
	has_kprobe_multi = bpf_core_type_exists(struct bpf_kprobe_multi_link);

	return 0;
}

SEC("kretsyscall/nanosleep")
int calib_exit(struct pt_regs *ctx)
{
	struct trace_kprobe *tk;
	__u64 fp, ip, i;
	int tid, off;

	tid = (__u32)bpf_get_current_pid_tgid();
	if (tid != my_tid)
		return 0;

	calib_exit_happened = true;

	/* get frame pointer */
	asm volatile ("%[fp] = r10" : [fp] "+r"(fp) :);

	for (i = 1; i <= MAX_ATTEMPTS; i++) {
		bpf_probe_read_kernel(&tk, sizeof(tk), (void *)(fp + i * sizeof(__u64)));
		ip = (__u64)BPF_CORE_READ(tk, rp.kp.addr);

		if (ip == entry_ip) {
			kret_ip_off = i;
			return 0;
		}
	}

	return 0;
}

