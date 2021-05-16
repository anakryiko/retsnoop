// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2021 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#undef bpf_printk
#define bpf_printk(fmt, ...)						\
({									\
	static const char ___fmt[] = fmt;				\
	bpf_trace_printk(___fmt, sizeof(___fmt), ##__VA_ARGS__);	\
})

/* these two are defined by custom BPF code outside of mass_attacher */
extern int handle_func_entry(void *ctx, u32 func_id, u64 func_ip);
extern int handle_func_exit(void *ctx, u32 func_id, u64 func_ip, u64 ret);

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, long);
	__type(value, unsigned);
} ip_to_id SEC(".maps");

#define MAX_CPU_CNT 256
#define MAX_CPU_MASK (MAX_CPU_CNT - 1)

int kret_ip_off = 0;
bool ready = false;

/* has to be called from entry-point BPF program */
static __always_inline u64 get_kret_caller_ip(void *ctx)
{
	struct trace_kprobe *tk = NULL;
	u64 fp, ip;

	/* get frame pointer */
	asm volatile ("%[fp] = r10" : [fp] "+r"(fp) :);

	if (kret_ip_off > 0)
		bpf_probe_read(&tk, sizeof(tk), (void *)(fp + kret_ip_off * sizeof(__u64)));

	ip = (__u64)BPF_CORE_READ(tk, rp.kp.addr);

	return ip;
}

SEC("kprobe/xxx")
int kentry(struct pt_regs *ctx)
{
	const char *name;
	u32 *id_ptr;
	long ip;

	if (!ready)
		return 0;

	ip = ctx->ip - 1;
	id_ptr = bpf_map_lookup_elem(&ip_to_id, &ip);
	if (!id_ptr) {
		bpf_printk("KENTRY UNRECOGNIZED IP %lx", ip);
		return 0;
	}

	handle_func_entry(ctx, *id_ptr, ip);
	return 0;
}

SEC("kretprobe/xxx")
int kexit(struct pt_regs *ctx)
{
	const char *name;
	u32 *id_ptr;
	long ip;

	if (!ready)
		return 0;

	ip = get_kret_caller_ip(ctx);
	id_ptr = bpf_map_lookup_elem(&ip_to_id, &ip);
	if (!id_ptr) {
		bpf_printk("KEXIT UNRECOGNIZED IP %lx", ip);
		return 0;
	}

	handle_func_exit(ctx, *id_ptr, ip, PT_REGS_RC(ctx));

	return 0;
}

int running[MAX_CPU_CNT] = {};

static __always_inline bool recur_enter(u32 cpu)
{
	if (running[cpu & MAX_CPU_MASK])
		return false;

	running[cpu & MAX_CPU_MASK] += 1;

	return true;
}

static __always_inline void recur_exit(u32 cpu)
{
	running[cpu & MAX_CPU_MASK] -= 1;
}

static __always_inline u64 get_ftrace_caller_ip(void *ctx, int arg_cnt)
{
	u64 off = 1 /* skip orig rbp */ + 1 /* skip reserved space for ret value */;
	u64 ip;

	if (arg_cnt <= 6)
		off += arg_cnt;
	else
		off += 6;
	off = (u64)ctx + off * 8;

	if (bpf_probe_read_kernel(&ip, sizeof(ip), (void *)off))
		return 0;

	ip -= 5; /* compensate for 5-byte fentry stub */
	return ip;
}

/* we need arg_cnt * sizeof(__u64) to be a constant, so need to inline */
static __always_inline int handle_fentry(void *ctx, int arg_cnt, bool entry)
{
	u32 *id_ptr, cpu;
	const char *name;
	long ip;

	if (!ready)
		return 0;

	cpu = bpf_get_smp_processor_id();
	if (!recur_enter(cpu))
		return 0;

	ip = get_ftrace_caller_ip(ctx, arg_cnt);
	id_ptr = bpf_map_lookup_elem(&ip_to_id, &ip);
	if (!id_ptr) {
		bpf_printk("UNRECOGNIZED IP %lx ARG_CNT %d ENTRY %d", ip, arg_cnt, entry);
		goto out;
	}

	if (entry) {
		handle_func_entry(ctx, *id_ptr, ip);
	} else {
		u64 res = *(u64 *)(ctx + sizeof(u64) * arg_cnt);

		handle_func_exit(ctx, *id_ptr, ip, res);
	}
out:
	recur_exit(cpu);
	return 0;
}

#define DEF_PROGS(arg_cnt) \
SEC("fentry/__x64_sys_read") \
int fentry ## arg_cnt(void *ctx) \
{ \
	return handle_fentry(ctx, arg_cnt, true); \
} \
SEC("fexit/__x64_sys_read") \
int fexit ## arg_cnt(void *ctx) \
{ \
	return handle_fentry(ctx, arg_cnt, false); \
}

DEF_PROGS(0)
DEF_PROGS(1)
DEF_PROGS(2)
DEF_PROGS(3)
DEF_PROGS(4)
DEF_PROGS(5)
DEF_PROGS(6)
