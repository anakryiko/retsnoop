// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2021 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "retsnoop.h"

static long (*bpf_get_branch_trace)(void *entries, __u32 size, __u64 flags) = (void *) 175;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define printk_is_sane (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_snprintf))

#define printk_needs_endline (!bpf_core_type_exists(struct trace_event_raw_bpf_trace_printk))

#define APPEND_ENDLINE(fmt) fmt[sizeof(fmt) - 2] = '\n'

#undef bpf_printk
#define bpf_printk(fmt, ...)						\
({									\
	static char ___fmt[] = fmt " ";					\
	if (printk_needs_endline)					\
		APPEND_ENDLINE(___fmt);					\
	bpf_trace_printk(___fmt, sizeof(___fmt), ##__VA_ARGS__);	\
})

#define barrier_var(var) asm volatile("" : "=r"(var) : "0"(var))

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct call_stack);
} stacks SEC(".maps");

const volatile bool verbose = false;
const volatile bool extra_verbose = false;
const volatile bool use_ringbuf = false;
const volatile int targ_tgid = 0;
const volatile bool emit_success_stacks = false;
const volatile bool emit_intermediate_stacks = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, bool);
	__uint(max_entries, 1); /* could be overriden from user-space */
} tgids_filter SEC(".maps");

const volatile __u32 tgid_allow_cnt = 0;
const volatile __u32 tgid_deny_cnt = 0;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, char[TASK_COMM_LEN]);
	__uint(max_entries, 1); /* could be overriden from user-space */
} comms_filter SEC(".maps");

const volatile __u32 comm_allow_cnt = 0;
const volatile __u32 comm_deny_cnt = 0;

const volatile __u64 duration_ns = 0;

char func_names[MAX_FUNC_CNT][MAX_FUNC_NAME_LEN] = {};
long func_ips[MAX_FUNC_CNT] = {};
int func_flags[MAX_FUNC_CNT] = {};

const volatile char spaces[512] = {};

static __always_inline int output_stack(void *ctx, void *map, struct call_stack *stack)
{
	stack->emit_ts = bpf_ktime_get_ns();

	if (duration_ns && stack->emit_ts - stack->func_lat[0] < duration_ns)
		return 0;

	if (!stack->is_err) {
		stack->kstack_sz = bpf_get_stack(ctx, &stack->kstack, sizeof(stack->kstack), 0);
		stack->lbr_entry_cnt = bpf_get_branch_trace(stack->lbr_entries, sizeof(stack->lbr_entries), 0);
	}

	/* use_ringbuf is read-only variable, so verifier will detect which of
	 * the branch is dead code and will eliminate it, so on old kernels
	 * bpf_ringbuf_output() won't be present in the resulting code
	 */
	if (use_ringbuf)
		return bpf_ringbuf_output(map, stack, sizeof(*stack), 0);
	else
		return bpf_perf_event_output(ctx, map, BPF_F_CURRENT_CPU, stack, sizeof(*stack));
}

static __noinline void save_stitch_stack(void *ctx, struct call_stack *stack)
{
	u64 d = stack->depth;
	u64 len = stack->max_depth - d;

	if (d >= MAX_FSTACK_DEPTH || len >= MAX_FSTACK_DEPTH) {
		bpf_printk("SHOULDN'T HAPPEN DEPTH %ld LEN %ld\n", d, len);
		return;
	}

	if (extra_verbose) {
		bpf_printk("CURRENT DEPTH %d..%d", stack->depth + 1, stack->max_depth);
		bpf_printk("SAVED DEPTH %d..%d", stack->saved_depth, stack->saved_max_depth);
	}

	/* we can stitch together stack subsections */
	if (stack->saved_depth && stack->max_depth + 1 == stack->saved_depth) {
		bpf_probe_read(stack->saved_ids + d, len * sizeof(stack->saved_ids[0]), stack->func_ids + d);
		bpf_probe_read(stack->saved_res + d, len * sizeof(stack->saved_res[0]), stack->func_res + d);
		bpf_probe_read(stack->saved_lat + d, len * sizeof(stack->saved_lat[0]), stack->func_lat + d);
		stack->saved_depth = stack->depth + 1;
		if (extra_verbose)
			bpf_printk("STITCHED STACK %d..%d to ..%d\n", stack->depth + 1, stack->max_depth, stack->saved_max_depth);
		return;
	}

	if (emit_intermediate_stacks) {
		/* we are partially overriding previous stack, so emit error stack, if present */
		if (extra_verbose)
			bpf_printk("EMIT PARTIAL STACK DEPTH %d..%d\n", stack->depth + 1, stack->max_depth);
		output_stack(ctx, &rb, stack);
	} else if (extra_verbose) {
		bpf_printk("RESETTING SAVED ERR STACK %d..%d to %d..\n",
			   stack->saved_depth, stack->saved_max_depth, stack->depth + 1);
	}

	bpf_probe_read(stack->saved_ids + d, len * sizeof(stack->saved_ids[0]), stack->func_ids + d);
	bpf_probe_read(stack->saved_res + d, len * sizeof(stack->saved_res[0]), stack->func_res + d);
	bpf_probe_read(stack->saved_lat + d, len * sizeof(stack->saved_lat[0]), stack->func_lat + d);

	stack->saved_depth = stack->depth + 1;
	stack->saved_max_depth = stack->max_depth;
}

static struct call_stack empty_stack;

static __noinline bool push_call_stack(void *ctx, u32 id, u64 ip)
{
	u32 pid = (u32)bpf_get_current_pid_tgid();
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

	if (stack->depth != stack->max_depth && stack->is_err)
		save_stitch_stack(ctx, stack);

	stack->func_ids[d] = id;
	stack->is_err = false;
	stack->depth = d + 1;
	stack->max_depth = d + 1;
	stack->func_lat[d] = bpf_ktime_get_ns();

	if (verbose) {
		const char *func_name = func_names[id & MAX_FUNC_MASK];

		if (printk_is_sane) {
			if (d == 0)
				bpf_printk("=== STARTING TRACING %s [COMM %s PID %d] ===",
					   func_name, stack->comm, pid);
			bpf_printk("    ENTER %s%s [...]", spaces + 2 *((255 - d) & 0xFF), func_name);
		} else {
			if (d == 0) {
				bpf_printk("=== STARTING TRACING %s [PID %d] ===", func_name, pid);
				bpf_printk("=== ...      TRACING [PID %d COMM %s] ===", pid, stack->comm);
			}
			bpf_printk("    ENTER [%d] %s [...]", d + 1, func_name);
		}
		//bpf_printk("PUSH(2) ID %d ADDR %lx NAME %s", id, ip, func_name);
	}

	return true;
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
	if (x > 0xffffffff)
		return false;
	return true;
}

/* all length should be the same */
char FMT_SUCC_VOID[]         = "    EXIT  %s%s [VOID]     ";
char FMT_SUCC_TRUE[]         = "    EXIT  %s%s [true]     ";
char FMT_SUCC_FALSE[]        = "    EXIT  %s%s [false]    ";
char FMT_FAIL_NULL[]         = "[!] EXIT  %s%s [NULL]     ";
char FMT_FAIL_PTR[]          = "[!] EXIT  %s%s [%d]       ";
char FMT_SUCC_PTR[]          = "    EXIT  %s%s [0x%lx]    ";
char FMT_FAIL_LONG[]         = "[!] EXIT  %s%s [%ld]      ";
char FMT_SUCC_LONG[]         = "    EXIT  %s%s [%ld]      ";
char FMT_FAIL_INT[]          = "[!] EXIT  %s%s [%d]       ";
char FMT_SUCC_INT[]          = "    EXIT  %s%s [%d]       ";

char FMT_SUCC_VOID_COMPAT[]  = "    EXIT  [%d] %s [VOID]  ";
char FMT_SUCC_TRUE_COMPAT[]  = "    EXIT  [%d] %s [true]  ";
char FMT_SUCC_FALSE_COMPAT[] = "    EXIT  [%d] %s [false] ";
char FMT_FAIL_NULL_COMPAT[]  = "[!] EXIT  [%d] %s [NULL]  ";
char FMT_FAIL_PTR_COMPAT[]   = "[!] EXIT  [%d] %s [%d]    ";
char FMT_SUCC_PTR_COMPAT[]   = "    EXIT  [%d] %s [0x%lx] ";
char FMT_FAIL_LONG_COMPAT[]  = "[!] EXIT  [%d] %s [%ld]   ";
char FMT_SUCC_LONG_COMPAT[]  = "    EXIT  [%d] %s [%ld]   ";
char FMT_FAIL_INT_COMPAT[]   = "[!] EXIT  [%d] %s [%d]    ";
char FMT_SUCC_INT_COMPAT[]   = "    EXIT  [%d] %s [%d]    ";

static __noinline void print_exit(void *ctx, __u32 d, __u32 id, long res)
{
	const char *func_name = func_names[id & MAX_FUNC_MASK];
	const size_t FMT_MAX_SZ = sizeof(FMT_SUCC_PTR_COMPAT); /* UPDATE IF NECESSARY */
	u32 flags, fmt_sz;
	const char *fmt;
	bool failed;

	if (printk_needs_endline) {
		/* before bpf_trace_printk() started using underlying
		 * tracepoint mechanism for logging to trace_pipe it didn't
		 * automatically append endline, so we need to adjust our
		 * format strings to have \n, otherwise we'll have a dump of
		 * unseparate log lines
		 */
		APPEND_ENDLINE(FMT_SUCC_VOID);
		APPEND_ENDLINE(FMT_SUCC_TRUE);
		APPEND_ENDLINE(FMT_SUCC_FALSE);
		APPEND_ENDLINE(FMT_FAIL_NULL);
		APPEND_ENDLINE(FMT_FAIL_PTR);
		APPEND_ENDLINE(FMT_SUCC_PTR);
		APPEND_ENDLINE(FMT_FAIL_LONG);
		APPEND_ENDLINE(FMT_SUCC_LONG);
		APPEND_ENDLINE(FMT_FAIL_INT);
		APPEND_ENDLINE(FMT_SUCC_INT);

		APPEND_ENDLINE(FMT_SUCC_VOID_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_TRUE_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_FALSE_COMPAT);
		APPEND_ENDLINE(FMT_FAIL_NULL_COMPAT);
		APPEND_ENDLINE(FMT_FAIL_PTR_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_PTR_COMPAT);
		APPEND_ENDLINE(FMT_FAIL_LONG_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_LONG_COMPAT);
		APPEND_ENDLINE(FMT_FAIL_INT_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_INT_COMPAT);
	}

	flags = func_flags[id & MAX_FUNC_MASK];
	if (flags & FUNC_RET_VOID) {
		fmt = printk_is_sane ? FMT_SUCC_VOID : FMT_SUCC_VOID_COMPAT;
		failed = false;
	} else if (flags & FUNC_RET_PTR) {
		/* consider NULL pointer an error */
		failed = (res == 0) || IS_ERR_VALUE(res);
		if (printk_is_sane)
			fmt = failed ? (res ? FMT_FAIL_PTR : FMT_FAIL_NULL) : FMT_SUCC_PTR;
		else
			fmt = failed ? (res ? FMT_FAIL_PTR_COMPAT : FMT_FAIL_NULL_COMPAT) : FMT_SUCC_PTR_COMPAT;
	} else if (flags & FUNC_RET_BOOL) {
		if (printk_is_sane)
			fmt = res ? FMT_SUCC_TRUE : FMT_SUCC_FALSE;
		else
			fmt = res ? FMT_SUCC_TRUE_COMPAT : FMT_SUCC_FALSE_COMPAT;
		failed = false;
	} else if (flags & FUNC_NEEDS_SIGN_EXT) {
		failed = IS_ERR_VALUE32(res);
		if (failed)
			fmt = printk_is_sane ? FMT_FAIL_INT : FMT_FAIL_INT_COMPAT;
		else
			fmt = printk_is_sane ? FMT_SUCC_INT : FMT_SUCC_INT_COMPAT;
	} else {
		failed = IS_ERR_VALUE(res);
		if (failed)
			fmt = printk_is_sane ? FMT_FAIL_LONG : FMT_FAIL_LONG_COMPAT;
		else
			fmt = printk_is_sane ? FMT_SUCC_LONG : FMT_SUCC_LONG_COMPAT;
	}

	if (printk_is_sane) {
		bpf_trace_printk(fmt, FMT_MAX_SZ, spaces + 2 * ((255 - d) & 0xff), func_name, res);
	} else {
		bpf_trace_printk(fmt, FMT_MAX_SZ, d + 1, func_name, res);
	}
	//bpf_printk("POP(1) ID %d ADDR %lx NAME %s", id, ip, func_name);
}

static __noinline bool pop_call_stack(void *ctx, u32 id, u64 ip, long res)
{
	const char *func_name = func_names[id & MAX_FUNC_MASK];
	u32 pid = (u32)bpf_get_current_pid_tgid();
	struct call_stack *stack;
	u32 exp_id, flags, fmt_sz;
	const char *fmt;
	bool failed;
	u64 d;

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

	flags = func_flags[id & MAX_FUNC_MASK];
	if (flags & FUNC_CANT_FAIL)
		failed = false;
	else if ((flags & FUNC_RET_PTR) && res == 0)
		/* consider NULL pointer an error as well */
		failed = true;
	else if (flags & FUNC_NEEDS_SIGN_EXT)
		failed = IS_ERR_VALUE32(res);
	else
		failed = IS_ERR_VALUE(res);

	if (verbose)
		print_exit(ctx, d, id, res);

	exp_id = stack->func_ids[d];
	if (exp_id != id) {
		const char *exp_func_name = func_names[exp_id & MAX_FUNC_MASK];
		u64 exp_ip;

		if (exp_id < MAX_FUNC_CNT)
			exp_ip = func_ips[exp_id];
		else
			exp_ip = 0;

		if (verbose) {
			bpf_printk("POP(0) UNEXPECTED PID %d DEPTH %d MAX DEPTH %d", pid, stack->depth, stack->max_depth);
			bpf_printk("POP(1) UNEXPECTED GOT  ID %d ADDR %lx NAME %s", id, ip, func_name);
			bpf_printk("POP(2) UNEXPECTED WANT ID %u ADDR %lx NAME %s", exp_id, exp_ip, exp_func_name);
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

	if (failed && !stack->is_err) {
		long cnt, i;

		stack->is_err = true;
		stack->max_depth = d + 1;
		stack->kstack_sz = bpf_get_stack(ctx, &stack->kstack, sizeof(stack->kstack), 0);

		stack->lbr_entry_cnt = bpf_get_branch_trace(stack->lbr_entries, sizeof(stack->lbr_entries), 0);
	}
	stack->depth = d;

	if (emit_success_stacks && !stack->is_err && d > 0 && d + 1 == stack->max_depth) {
		if (extra_verbose) {
			bpf_printk("EMIT DEEPEST SUCCESS STACK DEPTH %d\n", stack->max_depth);
		}
		output_stack(ctx, &rb, stack);
	}

	/* emit last complete stack trace */
	if (d == 0) {
		if (stack->is_err) {
			if (extra_verbose) {
				bpf_printk("EMIT ERROR STACK DEPTH %d (SAVED ..%d)\n",
					   stack->max_depth, stack->saved_max_depth);
			}
			output_stack(ctx, &rb, stack);
		} else if (emit_success_stacks) {
			if (extra_verbose) {
				bpf_printk("EMIT SUCCESS STACK DEPTH %d (SAVED ..%d)\n",
					   stack->max_depth, stack->saved_max_depth);
			}
			output_stack(ctx, &rb, stack);
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

static __always_inline bool tgid_allowed(void)
{
	bool *verdict_ptr;
	u32 tgid;

	/* if no PID filters -- allow everything */
	if (tgid_allow_cnt + tgid_deny_cnt == 0)
		return true;

	tgid = bpf_get_current_pid_tgid() >> 32;

	verdict_ptr = bpf_map_lookup_elem(&tgids_filter, &tgid);
	if (!verdict_ptr)
		/* if allowlist is non-empty, then PID didn't pass the check */
		return tgid_allow_cnt == 0;

	return *verdict_ptr;
}

static __always_inline bool comm_allowed(void)
{
	char comm[TASK_COMM_LEN] = {};
	bool *verdict_ptr;

	/* if no COMM filters -- allow everything */
	if (comm_allow_cnt + comm_deny_cnt == 0)
		return true;

	bpf_get_current_comm(comm, TASK_COMM_LEN);

	verdict_ptr = bpf_map_lookup_elem(&comms_filter, comm);
	if (!verdict_ptr)
		/* if allowlist is non-empty, then COMM didn't pass the check */
		return comm_allow_cnt == 0;

	return *verdict_ptr;
}

/* mass-attacher BPF library is calling this function, so it should be global */
__hidden int handle_func_entry(void *ctx, u32 func_id, u64 func_ip)
{
	if (!tgid_allowed() || !comm_allowed())
		return 0;

	push_call_stack(ctx, func_id, func_ip);
	return 0;
}

/* mass-attacher BPF library is calling this function, so it should be global */
__hidden int handle_func_exit(void *ctx, u32 func_id, u64 func_ip, u64 ret)
{
	if (!tgid_allowed() || !comm_allowed())
		return 0;

	pop_call_stack(ctx, func_id, func_ip, ret);
	return 0;
}
