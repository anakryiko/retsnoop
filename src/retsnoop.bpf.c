// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2021 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "retsnoop.h"

#undef bpf_printk
#define bpf_printk(fmt, ...)						\
({									\
	static const char ___fmt[] = fmt;				\
	bpf_trace_printk(___fmt, sizeof(___fmt), ##__VA_ARGS__);	\
})

#define barrier_var(var) asm volatile("" : "=r"(var) : "0"(var))

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct call_stack);
} stacks SEC(".maps");

const volatile bool verbose = false;
const volatile bool use_ringbuf = false;
const volatile int targ_tgid = 0;
const volatile bool emit_success_stacks = false;
const volatile bool emit_intermediate_stacks = false;

char func_names[MAX_FUNC_CNT][MAX_FUNC_NAME_LEN] = {};
long func_ips[MAX_FUNC_CNT] = {};
int func_flags[MAX_FUNC_CNT] = {};

static __always_inline int ringbuf_output(void *ctx, void *map, struct call_stack *stack)
{
	/* use_ringbuf is read-only variable, so verifier will detect which of
	 * the branch is dead code and will eliminate it, so on old kernels
	 * bpf_ringbuf_output() won't be present in the resulting code
	 */
	if (use_ringbuf)
		return bpf_ringbuf_output(map, stack, sizeof(*stack), 0);
	else
		return bpf_perf_event_output(ctx, map, BPF_F_CURRENT_CPU, stack, sizeof(*stack));
}

static __noinline void save_stitch_stack(struct call_stack *stack)
{
	if (verbose) {
		bpf_printk("CURRENT DEPTH %d..%d", stack->depth, stack->max_depth);
		bpf_printk("SAVED DEPTH %d..%d", stack->saved_depth, stack->saved_max_depth);
	}

	if (!stack->saved_depth || stack->max_depth + 1 != stack->saved_depth) {
		bpf_probe_read(stack->saved_ids, sizeof(stack->saved_ids), stack->func_ids);
		bpf_probe_read(stack->saved_res, sizeof(stack->saved_res), stack->func_res);
		bpf_probe_read(stack->saved_lat, sizeof(stack->saved_lat), stack->func_lat);
		stack->saved_depth = stack->depth + 1;
		stack->saved_max_depth = stack->max_depth;
		if (verbose)
			bpf_printk("RESETTING SAVED ERR STACK\n");
	} else {
		bpf_probe_read(stack->saved_ids, sizeof(stack->saved_ids), stack->func_ids);
		bpf_probe_read(stack->saved_res, sizeof(stack->saved_res), stack->func_res);
		bpf_probe_read(stack->saved_lat, sizeof(stack->saved_lat), stack->func_lat);
		stack->saved_depth = stack->depth + 1;
		stack->saved_max_depth = stack->max_depth;
		if (verbose)
			bpf_printk("NEED TO APPEND BUT RESETTING SAVED ERR STACK\n");
	}
	/* we are partially overriding previous stack, so emit error
	 * stack, if present
	 */
	//bpf_printk("CPU %d EMITTING ERROR STACK (DEPTH %d MAX DEPTH %d)!!!", cpu, stack->depth, stack->max_depth);
	//ringbuf_output(ctx, &rb, stack);
}

static struct call_stack empty_stack;

static __noinline bool push_call_stack(void *ctx, u32 pid, u32 id, u64 ip)
{
	struct call_stack *stack;
	u64 d;

	stack = bpf_map_lookup_elem(&stacks, &pid);
	if (!stack) {
		if (!(func_flags[id & MAX_FUNC_MASK] & FUNC_IS_ENTRY))
			return false;

		bpf_map_update_elem(&stacks, &pid, &empty_stack, BPF_ANY);
		stack = bpf_map_lookup_elem(&stacks, &pid);
		if (!stack)
			return false;

		stack->pid = pid;
		bpf_get_current_comm(&stack->comm, sizeof(stack->comm));
	}

	d = stack->depth;
	barrier_var(d);
	if (d >= MAX_FSTACK_DEPTH)
		return false;

	if (stack->depth != stack->max_depth && stack->is_err) {
		if (emit_intermediate_stacks)
			ringbuf_output(ctx, &rb, stack);
		save_stitch_stack(stack);
	}

	/*
	barrier_var(d);
	if (d >= MAX_FSTACK_DEPTH)
		return false;
	*/

	stack->func_ids[d] = id;
	stack->is_err = false;
	stack->depth = d + 1;
	stack->max_depth = d + 1;
	stack->func_lat[d] = bpf_ktime_get_ns();

	if (verbose) {
		bpf_printk("PUSH(1) PID %d DEPTH %d NAME %s", pid, d + 1, func_names[id & MAX_FUNC_MASK]);
		bpf_printk("PUSH(2) ID %d ADDR %lx NAME %s", id, ip, func_names[id & MAX_FUNC_MASK]);
	}

	return true;
}


static __noinline bool pop_call_stack(void *ctx, u32 id, u64 ip, long res, bool is_err)
{
	u32 cpu = bpf_get_smp_processor_id();
	u32 pid = (u32)bpf_get_current_pid_tgid();
	struct call_stack *stack;
	u64 d, actual_ip;
	u32 actual_id;

	stack = bpf_map_lookup_elem(&stacks, &pid);
	if (!stack)
		return false;

	d = stack->depth;
	if (d == 0)
		return false;
 
	d -= 1;

	barrier_var(d);
	if (d >= MAX_FSTACK_DEPTH)
		return false;

	if (verbose) {
		bpf_printk("POP(0) PID %d DEPTH %d MAX DEPTH %d", pid, stack->depth, stack->max_depth);
		bpf_printk("POP(1) ID %d ADDR %lx NAME %s", id, ip, func_names[id & MAX_FUNC_MASK]);
		if (is_err)
			bpf_printk("POP(2) ERROR RESULT %ld (%d)", res, res);
		else
			bpf_printk("POP(2) SUCCESS RESULT %ld (%d)", res, res);
	}

	actual_id = stack->func_ids[d];
	if (actual_id != id) {
		if (actual_id < MAX_FUNC_CNT)
			actual_ip = func_ips[actual_id];
		else
			actual_ip = 0;

		if (verbose) {
			bpf_printk("POP(0) UNEXPECTED PID %d DEPTH %d MAX DEPTH %d", pid, stack->depth, stack->max_depth);
			bpf_printk("POP(1) UNEXPECTEC GOT ID %d ADDR %lx NAME %s", id, ip, func_names[id & MAX_FUNC_MASK]);
			bpf_printk("POP(2) UNEXPECTED. WANTED ID %u ADDR %lx NAME %s",
				   actual_id, actual_ip, func_names[actual_id & MAX_FUNC_MASK]);
		}

		stack->depth = 0;
		stack->max_depth = 0;
		stack->is_err = false;
		stack->kstack_sz = 0;

		bpf_map_delete_elem(&stacks, &pid);

		return false;
	}

	stack->func_res[d] = res;
	stack->func_lat[d] = bpf_ktime_get_ns() - stack->func_lat[d];

	if (is_err && !stack->is_err) {
		stack->is_err = true;
		stack->max_depth = d + 1;

		stack->kstack_sz = bpf_get_stack(ctx, &stack->kstack, sizeof(stack->kstack), 0);
	}
	stack->depth = d;

	/* emit last complete stack trace */
	if (d == 0) {
		if (stack->is_err) {
			if (verbose)
				bpf_printk("PID %d EMITTING DEPTH 0 ERROR STACK MAX DEPTH %d\n", pid, stack->max_depth);
			ringbuf_output(ctx, &rb, stack);
		} else if (emit_success_stacks) {
			if (verbose)
				bpf_printk("PID %d EMITTING DEPTH 0 SUCCESS STACK MAX DEPTH %d\n", pid, stack->max_depth);
			ringbuf_output(ctx, &rb, stack);
		}
		stack->is_err = false;
		stack->saved_depth = 0;
		stack->saved_max_depth = 0;
		stack->depth = 0;
		stack->max_depth = 0;
		stack->kstack_sz = 0;

		bpf_map_delete_elem(&stacks, &pid);
	}

	return true;
}

/* mass-attacher BPF library is calling this function, so it should be global */
__hidden int handle_func_entry(void *ctx, u32 cpu, u32 func_id, u64 func_ip)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = (u32)pid_tgid;
	u32 tgid = pid_tgid >> 32;

	if (targ_tgid && targ_tgid != tgid)
		return false;

	push_call_stack(ctx, pid, func_id, func_ip);
	return 0;
}

#define MAX_ERRNO 4095

static __always_inline bool IS_ERR_VALUE(long x)
{
	return (unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO;
}

static __always_inline bool IS_ERR_VALUE32(u64 x)
{
	/* Due to BPF verifier limitations, it's really hard to do int to long
	 * sign extension generically, because some return types might be
	 * pointers and BPF verifier really hates us for treating pointer as
	 * integer and doing arbitrary (bit shifts) arithmetics on it.  So
	 * instead we just assume we have a 32-bit signed integer and check
	 * manually that it's value unsigned value lies in [-4095, 1] range.
	 * -1 is 0xffffffff, -4095 is 0xfffff001. Easy.
	 */
	if (x < 0xfffff001)
		return false;
	/* prevent clever Clang optimizaations involving math */
	barrier_var(x);
	if ( x > 0xffffffff)
		return false;
	return true;
}

/* mass-attacher BPF library is calling this function, so it should be global */
__hidden int handle_func_exit(void *ctx, u32 cpu, u32 func_id, u64 func_ip, u64 ret)
{
	int flags;
	bool failed = false;

	if (targ_tgid && targ_tgid != (bpf_get_current_pid_tgid() >> 32))
		return false;

	flags = func_flags[func_id & MAX_FUNC_MASK];
	if (flags & FUNC_CANT_FAIL)
		goto pop;

	if (flags & FUNC_NEEDS_SIGN_EXT)
		failed = IS_ERR_VALUE32(ret);
	else
		failed = IS_ERR_VALUE(ret);

	/* consider NULL pointer an error */
	if ((flags & FUNC_RET_PTR) && ret == 0)
		failed = true;

pop:
	pop_call_stack(ctx, func_id, func_ip, ret, failed);
	return 0;
}
