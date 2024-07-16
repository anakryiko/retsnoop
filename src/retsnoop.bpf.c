// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2021 Facebook */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "retsnoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef ENOSPC
#define ENOSPC 28
#endif

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

#define log(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#define vlog(fmt, ...) do { if (verbose) { bpf_printk(fmt, ##__VA_ARGS__); }  } while (0)
#define dlog(fmt, ...) do { if (extra_verbose) { bpf_printk(fmt, ##__VA_ARGS__); } } while (0)

#define __memcpy(dst, src, sz) bpf_probe_read_kernel(dst, sz, src)

struct session {
	long scratch; /* for obfuscating pointers to be read as integers */

	bool defunct;
	bool start_emitted;

	int next_seq_id;

	struct perf_branch_entry lbrs[MAX_LBR_ENTRIES];
	long lbrs_sz;

	struct call_stack stack;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct session);
} sessions SEC(".maps");

const volatile bool verbose = false;
const volatile bool extra_verbose = false;
const volatile bool use_lbr = true;
const volatile int targ_tgid = -1;
const volatile bool emit_success_stacks = false;
const volatile bool emit_func_trace = false;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, bool);
	__uint(max_entries, 1); /* could be overriden from user-space */
} tgids_filter SEC(".maps");

const volatile __u32 tgid_allow_cnt = -1;
const volatile __u32 tgid_deny_cnt = -1;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, char[TASK_COMM_LEN]);
	__uint(max_entries, 1); /* could be overriden from user-space */
} comms_filter SEC(".maps");

const volatile __u32 comm_allow_cnt = -1;
const volatile __u32 comm_deny_cnt = -1;

const volatile __u64 duration_ns = -1;

const volatile char spaces[512] = {};

/* provided by mass_attach.bpf.c */
int copy_lbrs(void *dst, size_t dst_sz);


/* dynamically sized from the user space */
struct func_info func_infos[1] SEC(".data.func_infos");
const volatile __u32 func_info_mask;

static __always_inline const struct func_info *func_info(__u32 id)
{
	return &func_infos[id & func_info_mask];
}

static __noinline void save_stitch_stack(void *ctx, struct call_stack *stack)
{
	u64 d = stack->depth;
	u64 len = stack->max_depth - d;

	if (d >= MAX_FSTACK_DEPTH || len >= MAX_FSTACK_DEPTH) {
		log("SHOULDN'T HAPPEN DEPTH %ld LEN %ld\n", d, len);
		return;
	}

	dlog("CURRENT DEPTH %d..%d", stack->depth + 1, stack->max_depth);
	dlog("SAVED DEPTH %d..%d", stack->saved_depth, stack->saved_max_depth);

	/* we can stitch together stack subsections */
	if (stack->saved_depth && stack->max_depth + 1 == stack->saved_depth) {
		bpf_probe_read_kernel(stack->saved_ids + d, len * sizeof(stack->saved_ids[0]), stack->func_ids + d);
		bpf_probe_read_kernel(stack->saved_res + d, len * sizeof(stack->saved_res[0]), stack->func_res + d);
		bpf_probe_read_kernel(stack->saved_lat + d, len * sizeof(stack->saved_lat[0]), stack->func_lat + d);
		stack->saved_depth = stack->depth + 1;
		dlog("STITCHED STACK %d..%d to ..%d\n",
		     stack->depth + 1, stack->max_depth, stack->saved_max_depth);
		return;
	}

	dlog("RESETTING SAVED ERR STACK %d..%d to %d..\n",
	     stack->saved_depth, stack->saved_max_depth, stack->depth + 1);

	bpf_probe_read_kernel(stack->saved_ids + d, len * sizeof(stack->saved_ids[0]), stack->func_ids + d);
	bpf_probe_read_kernel(stack->saved_res + d, len * sizeof(stack->saved_res[0]), stack->func_res + d);
	bpf_probe_read_kernel(stack->saved_lat + d, len * sizeof(stack->saved_lat[0]), stack->func_lat + d);

	stack->saved_depth = stack->depth + 1;
	stack->saved_max_depth = stack->max_depth;
}

static const struct session empty_session;

static bool emit_session_start(struct session *sess)
{
	struct session_start *r;

	r = bpf_ringbuf_reserve(&rb, sizeof(*r), 0);
	if (!r)
		return false;

	r->type = REC_SESSION_START;
	r->pid = sess->stack.pid;
	r->tgid = sess->stack.tgid;
	r->start_ts = sess->stack.start_ts;
	__builtin_memcpy(r->task_comm, sess->stack.task_comm, sizeof(sess->stack.task_comm));
	__builtin_memcpy(r->proc_comm, sess->stack.proc_comm, sizeof(sess->stack.proc_comm));

	bpf_ringbuf_submit(r, 0);

	return true;
}

static __noinline bool push_call_stack(void *ctx, u32 id, u64 ip)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = (u32)pid_tgid;
	struct session *sess;
	u64 d;

	sess = bpf_map_lookup_elem(&sessions, &pid);
	if (!sess) {
		struct task_struct *tsk;

		if (!(func_info(id)->flags & FUNC_IS_ENTRY))
			return false;

		bpf_map_update_elem(&sessions, &pid, &empty_session, BPF_ANY);
		sess = bpf_map_lookup_elem(&sessions, &pid);
		if (!sess)
			return false;

		sess->stack.type = REC_CALL_STACK;
		sess->stack.start_ts = bpf_ktime_get_ns();
		sess->stack.pid = pid;
		sess->stack.tgid = (u32)(pid_tgid >> 32);
		bpf_get_current_comm(&sess->stack.task_comm, sizeof(sess->stack.task_comm));
		tsk = (void *)bpf_get_current_task();
		BPF_CORE_READ_INTO(&sess->stack.proc_comm, tsk, group_leader, comm);

		if (emit_func_trace) {
			if (!emit_session_start(sess)) {
				vlog("DEFUNCT SESSION TID/PID %d/%d: failed to send SESSION_START record!\n",
				     sess->stack.pid, sess->stack.tgid);
				sess->defunct = true;
				goto out_defunct;
			} else {
				sess->start_emitted = true;
			}
		}
	}

out_defunct:
	/* if we failed to send out REC_SESSION_START, update depth and bail */
	if (sess->defunct) {
		sess->stack.depth++;
		return false;
	}

	d = sess->stack.depth;
	barrier_var(d);
	if (d >= MAX_FSTACK_DEPTH)
		return false;

	if (sess->stack.depth != sess->stack.max_depth && sess->stack.is_err)
		save_stitch_stack(ctx, &sess->stack);

	sess->stack.func_ids[d] = id;
	sess->stack.is_err = false;
	sess->stack.depth = d + 1;
	sess->stack.max_depth = d + 1;
	sess->stack.func_lat[d] = bpf_ktime_get_ns();

	sess->next_seq_id++;

	if (emit_func_trace) {
		struct func_trace_entry *fe;

		fe = bpf_ringbuf_reserve(&rb, sizeof(*fe), 0);
		if (!fe)
			goto skip_ft_entry;

		fe->type = REC_FUNC_TRACE_ENTRY;
		fe->ts = bpf_ktime_get_ns();
		fe->pid = pid;
		fe->seq_id = sess->next_seq_id - 1;
		fe->depth = d + 1;
		fe->func_id = id;
		fe->func_lat = 0;
		fe->func_res = 0;

		bpf_ringbuf_submit(fe, 0);
skip_ft_entry:;
	}

	if (verbose) {
		const char *func_name = func_info(id)->name;

		if (printk_is_sane) {
			if (d == 0)
				log("=== STARTING TRACING %s [COMM %s PID %d] ===",
				    func_name, sess->stack.task_comm, pid);
			log("    ENTER %s%s [...]", spaces + 2 * ((255 - d) & 0xFF), func_name);
		} else {
			if (d == 0) {
				log("=== STARTING TRACING %s [PID %d] ===", func_name, pid);
				log("=== ...      TRACING [PID %d COMM %s] ===", pid, sess->stack.task_comm);
			}
			log("    ENTER [%d] %s [...]", d + 1, func_name);
		}
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
	const struct func_info *fi;
	const char *func_name = fi->name;
	const size_t FMT_MAX_SZ = sizeof(FMT_SUCC_PTR_COMPAT); /* UPDATE IF NECESSARY */
	u32 flags, fmt_sz;
	const char *fmt;
	bool failed;

	fi = func_info(id);
	func_name = fi->name;
	flags = fi->flags;

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
		failed = IS_ERR_VALUE32((u32)res);
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
}

static void reset_session(struct session *sess)
{
	sess->defunct = false;
	sess->start_emitted = false;

	sess->stack.is_err = false;
	sess->stack.saved_depth = 0;
	sess->stack.saved_max_depth = 0;
	sess->stack.depth = 0;
	sess->stack.max_depth = 0;
	sess->stack.kstack_sz = 0;

	sess->lbrs_sz = 0;
}

static int submit_session(void *ctx, struct session *sess)
{
	bool emit_session;

	sess->stack.emit_ts = bpf_ktime_get_ns();

	emit_session = sess->stack.is_err || emit_success_stacks;
	if (duration_ns && sess->stack.emit_ts - sess->stack.func_lat[0] < duration_ns)
		emit_session = false;

	if (emit_session) {
		dlog("EMIT %s STACK DEPTH %d (SAVED ..%d)\n",
		     sess->stack.is_err ? "ERROR" : "SUCCESS",
		     sess->stack.max_depth, sess->stack.saved_max_depth);
	}

	if (emit_session && !sess->start_emitted) {
		if (!emit_session_start(sess)) {
			vlog("DEFUNCT SESSION TID/PID %d/%d: failed to send SESSION data!\n",
			     sess->stack.pid, sess->stack.tgid);
			sess->defunct = true;
			return -EINVAL;
		}
		sess->start_emitted = true;
	}

	if (emit_session && use_lbr) {
		struct lbr_stack *r;

		if (sess->lbrs_sz <= 0)
			goto skip_lbrs;

		r = bpf_ringbuf_reserve(&rb, sizeof(*r), 0);
		if (!r) {
			/* record that we failed to submit LBR data */
			sess->lbrs_sz = -ENOSPC;
			goto skip_lbrs;
		}

		r->type = REC_LBR_STACK;
		r->pid = sess->stack.pid;
		r->lbrs_sz = sess->lbrs_sz;
		__memcpy(r->lbrs, sess->lbrs, sizeof(sess->lbrs));

		bpf_ringbuf_submit(r, 0);
skip_lbrs:;
	}

	if (emit_session) {
		if (!sess->stack.is_err)
			sess->stack.kstack_sz = bpf_get_stack(ctx, &sess->stack.kstack, sizeof(sess->stack.kstack), 0);
		sess->stack.last_seq_id = sess->next_seq_id - 1;

		/* might fail */
		bpf_ringbuf_output(&rb, &sess->stack, sizeof(sess->stack), 0);
	}

	if (emit_session || sess->start_emitted) {
		struct session_end *r;

		r = bpf_ringbuf_reserve(&rb, sizeof(*r), 0);
		if (!r)
			return -EINVAL;

		r->type = REC_SESSION_END;
		r->pid = sess->stack.pid;
		r->emit_ts = bpf_ktime_get_ns();
		r->ignored = !emit_session;
		r->is_err = sess->stack.is_err;
		r->last_seq_id = sess->next_seq_id - 1;
		r->lbrs_sz = sess->lbrs_sz;

		bpf_ringbuf_submit(r, 0);
	}

	return 0;
}

static __noinline bool pop_call_stack(void *ctx, u32 id, u64 ip, long res)
{
	const struct func_info *fi;
	const char *func_name;
	struct session *sess;
	u32 pid, exp_id, flags, fmt_sz;
	const char *fmt;
	bool failed;
	u64 d, lat;

	pid = (u32)bpf_get_current_pid_tgid();
	sess = bpf_map_lookup_elem(&sessions, &pid);
	if (!sess)
		return false;

	/* if we failed to send out REC_SESSION_START, clean up and send nothing else */
	if (sess->defunct) {
		sess->stack.depth--;
		if (sess->stack.depth == 0) {
			reset_session(sess);
			bpf_map_delete_elem(&sessions, &pid);
			vlog("DEFUNCT SESSION TID/PID %d/%d: SESSION_END, no data was collected!\n",
			     pid, sess->stack.tgid);
		}
		return false;
	}

	sess->next_seq_id++;

	d = sess->stack.depth;
	if (d == 0)
		return false;

	d -= 1;
	barrier_var(d);
	if (d >= MAX_FSTACK_DEPTH)
		return false;

	fi = func_info(id);
	func_name = fi->name;
	flags = fi->flags;

	/* obfuscate pointers (tracked in fentry/fexit mode by BPF verifier
	 * for pointer-returning functions) to be interpreted as opaque
	 * integers
	 */
	sess->scratch = res;
	barrier_var(res);
	res = sess->scratch;

	if (flags & FUNC_CANT_FAIL)
		failed = false;
	else if ((flags & FUNC_RET_PTR) && res == 0)
		/* consider NULL pointer an error as well */
		failed = true;
	else if (flags & FUNC_NEEDS_SIGN_EXT)
		failed = IS_ERR_VALUE32((u32)res);
	else
		failed = IS_ERR_VALUE(res);

	lat = bpf_ktime_get_ns() - sess->stack.func_lat[d];

	if (emit_func_trace) {
		struct func_trace_entry *fe;

		fe = bpf_ringbuf_reserve(&rb, sizeof(*fe), 0);
		if (!fe)
			goto skip_ft_exit;

		fe->type = REC_FUNC_TRACE_EXIT;
		fe->ts = bpf_ktime_get_ns();
		fe->pid = pid;
		fe->seq_id = sess->next_seq_id - 1;
		fe->depth = d + 1;
		fe->func_id = id;
		fe->func_lat = lat;
		fe->func_res = res;

		bpf_ringbuf_submit(fe, 0);
skip_ft_exit:;
	}
	if (verbose)
		print_exit(ctx, d, id, res);

	exp_id = sess->stack.func_ids[d];
	if (exp_id != id) {
		const struct func_info *exp_fi = func_info(exp_id);

		vlog("POP(0) UNEXPECTED PID %d DEPTH %d MAX DEPTH %d",
		     pid, sess->stack.depth, sess->stack.max_depth);
		vlog("POP(1) UNEXPECTED GOT  ID %d ADDR %lx NAME %s",
		     id, ip, func_name);
		vlog("POP(2) UNEXPECTED WANT ID %u ADDR %lx NAME %s",
		     exp_id, exp_fi->ip, exp_fi->name);

		reset_session(sess);
		bpf_map_delete_elem(&sessions, &pid);

		return false;
	}

	sess->stack.func_res[d] = res;
	sess->stack.func_lat[d] = lat;

	if (failed && !sess->stack.is_err) {
		sess->stack.is_err = true;
		sess->stack.max_depth = d + 1;
		sess->stack.kstack_sz = bpf_get_stack(ctx, &sess->stack.kstack, sizeof(sess->stack.kstack), 0);
		sess->lbrs_sz = copy_lbrs(&sess->lbrs, sizeof(sess->lbrs));
	} else if (emit_success_stacks && d + 1 == sess->stack.max_depth) {
		sess->stack.kstack_sz = bpf_get_stack(ctx, &sess->stack.kstack, sizeof(sess->stack.kstack), 0);
		sess->lbrs_sz = copy_lbrs(&sess->lbrs, sizeof(sess->lbrs));
	}
	sess->stack.depth = d;

	/* emit last complete stack trace */
	if (d == 0) {
		/* can fail or do nothing for current session */
		submit_session(ctx, sess);

		reset_session(sess);
		bpf_map_delete_elem(&sessions, &pid);
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
