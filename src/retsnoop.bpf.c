// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2021 Facebook */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "retsnoop.h"

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

#define log(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#define vlog(fmt, ...) do { if (verbose) { bpf_printk(fmt, ##__VA_ARGS__); }  } while (0)
#define dlog(fmt, ...) do { if (extra_verbose) { bpf_printk(fmt, ##__VA_ARGS__); } } while (0)

#define __memcpy(dst, src, sz) bpf_probe_read_kernel(dst, sz, src)

static inline void atomic_inc(long *value)
{
	(void)__atomic_add_fetch(value, 1, __ATOMIC_RELAXED);
}

static inline void atomic_add(long *value, long n)
{
	(void)__atomic_add_fetch(value, n, __ATOMIC_RELAXED);
}

enum session_type {
	SESSION_FINAL,
	SESSION_STITCH,
	SESSION_PROBE,
};

struct session {
	int sess_id;
	int pid, tgid;
	long start_ts;
	char task_comm[16], proc_comm[16];

	long scratch; /* for obfuscating pointers to be read as integers */

	bool defunct;
	bool start_emitted;
	bool is_err;

	int next_seq_id;

	int dropped_records;

	struct perf_branch_entry lbrs[MAX_LBR_ENTRIES];
	long lbrs_sz;

	struct perf_branch_entry saved_lbrs[MAX_LBR_ENTRIES];
	long saved_lbrs_sz;

	unsigned short func_ids[MAX_FSTACK_DEPTH];
	int seq_ids[MAX_FSTACK_DEPTH];
	long func_res[MAX_FSTACK_DEPTH];
	long func_lat[MAX_FSTACK_DEPTH];
	unsigned depth;
	unsigned max_depth;

	unsigned short saved_ids[MAX_FSTACK_DEPTH];
	int saved_seq_ids[MAX_FSTACK_DEPTH];
	long saved_res[MAX_FSTACK_DEPTH];
	long saved_lat[MAX_FSTACK_DEPTH];
	unsigned saved_depth;
	unsigned saved_max_depth;

	int saved_last_seq_id;

	long kstack[MAX_KSTACK_DEPTH];
	long kstack_sz;

	long saved_kstack[MAX_KSTACK_DEPTH];
	long saved_kstack_sz;
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
const volatile bool emit_call_stack = true;
const volatile bool emit_func_trace = true;
const volatile bool emit_success_stacks = true;
const volatile bool emit_interim_stacks = true;
const volatile bool capture_fn_args = true;
const volatile bool capture_ctx_args = true;
const volatile bool capture_raw_ptrs = true;
const volatile bool use_lbr = true;
const volatile bool use_kprobes = true;

const volatile int args_max_total_args_sz = DEFAULT_FNARGS_TOTAL_ARGS_SZ;
const volatile int args_max_sized_arg_sz = DEFAULT_FNARGS_SIZED_ARG_SZ;
const volatile int args_max_str_arg_sz = DEFAULT_FNARGS_STR_ARG_SZ;
const volatile int args_max_any_arg_sz = DEFAULT_FNARGS_SIZED_ARG_SZ > DEFAULT_FNARGS_STR_ARG_SZ
				       ? DEFAULT_FNARGS_SIZED_ARG_SZ
				       : DEFAULT_FNARGS_STR_ARG_SZ;

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

struct stats stats = {};

static void stat_dropped_record(struct session *sess)
{
	if (sess->dropped_records == 0)
		/* only count each incomplete session once */
		atomic_inc(&stats.incomplete_sessions);
	sess->dropped_records++;
}

/* provided by mass_attach.bpf.c */
int copy_lbrs(void *dst, size_t dst_sz);

/* dynamically sized from the user space */
struct func_info func_infos[1] SEC(".data.func_infos");
const volatile __u32 func_info_mask;

static __always_inline const struct func_info *func_info(u32 id)
{
	return &func_infos[id & func_info_mask];
}

/* dynamically sized from the user space */
struct ctxargs_info ctxargs_infos[1] SEC(".data.ctxargs_infos");
const volatile __u32 ctxargs_info_mask;

static __always_inline const struct ctxargs_info *ctxargs_info(u32 id)
{
	return &ctxargs_infos[id & ctxargs_info_mask];
}

#ifdef __TARGET_ARCH_x86
static u64 get_arg_reg_value(void *ctx, u32 arg_idx)
{
	if (use_kprobes) {
		struct pt_regs *regs = ctx;

		switch (arg_idx) {
			case 0: return PT_REGS_PARM1(regs);
			case 1: return PT_REGS_PARM2(regs);
			case 2: return PT_REGS_PARM3(regs);
			case 3: return PT_REGS_PARM4(regs);
			case 4: return PT_REGS_PARM5(regs);
			case 5: return PT_REGS_PARM6(regs);
			default: return 0;
		}
	} else {
		u64 *args = ctx, val;

		bpf_probe_read_kernel(&val, sizeof(val), &args[arg_idx]);
		return val;
	}
}

static __always_inline u64 get_stack_pointer(void *ctx)
{
	u64 sp;

	if (use_kprobes) {
		sp = PT_REGS_SP((struct pt_regs *)ctx);
		barrier_var(sp);
	} else {
		/* current FENTRY doesn't support attaching to functions that
		 * pass arguments on the stack, so we don't really need to
		 * implement this
		 */
		sp = 0;
		barrier_var(sp);
	}

	return sp;
}
#else /* !__TARGET_ARCH_x86 */
static u64 get_arg_reg_value(void *ctx, u32 arg_idx) { return 0; }
static u64 get_stack_pointer(void *ctx) { return 0; }
#endif

static __always_inline u64 coerce_size(u64 val, int sz)
{
	int shift = (8 - sz) * 8;
	return (val << shift) >> shift;
}

static __always_inline bool is_kernel_addr(void *addr)
{
	return (long)addr <= 0;
}

struct data_capture_ctx {
	char *data;
	unsigned short *data_len;
	short *arg_lens;
	unsigned short *arg_ptrs;
	bool record_ptr;
	bool is_str;
};

static void capture_vararg(struct data_capture_ctx *dctx, u32 arg_idx, void *src)
{
	size_t data_off;
	void *dst;
	int err, kind, len;

	data_off = *dctx->data_len;
	barrier_var(data_off); /* prevent compiler from re-reading it */

	if (data_off >= args_max_total_args_sz) {
		dctx->arg_lens[arg_idx] = -ENOSPC;
		return;
	}

	dst = dctx->data + data_off;

	/* at least capture raw 8 byte value */
	*(long *)dst = (long)src;
	len = 8;
	dst += 8;
	*dctx->data_len += 8;

	/* if this looks like a kernel addrs, also try to read kernel string */
	if (is_kernel_addr(src)) {
		/* in this case we mark that we have a raw pointer value */
		*dctx->arg_ptrs |= (1 << arg_idx);

		err = bpf_probe_read_kernel_str(dst, args_max_str_arg_sz, src);
		if (err < 0) {
			dctx->arg_lens[arg_idx] = err;
			return;
		}

		len = err;
		*dctx->data_len += (len + 7) / 8 * 8;
	}

	dctx->arg_lens[arg_idx] = len;
}

static void capture_arg(struct data_capture_ctx *dctx, u32 arg_idx,
			void *src, u64 len)
{
	size_t data_off;
	void *dst;
	int err;

	if (src == NULL) {
		dctx->arg_lens[arg_idx] = -ENODATA;
		return;
	}

	data_off = *dctx->data_len;
	barrier_var(data_off); /* prevent compiler from re-reading it */

	if (data_off >= args_max_total_args_sz) {
		dctx->arg_lens[arg_idx] = -ENOSPC;
		return;
	}

	dst = dctx->data + data_off;

	if (capture_raw_ptrs && dctx->record_ptr) {
		*(long *)dst = (long)src;
		dst += 8;
		*dctx->arg_ptrs |= (1 << arg_idx);
		*dctx->data_len += 8;
	}

	/* ensure compiler won't reload len if capture_arg() is inlined */
	barrier_var(len);

	if (dctx->is_str) {
		if (len > args_max_str_arg_sz) /* truncate, if necessary */
			len = args_max_str_arg_sz;
		if (is_kernel_addr(src))
			err = bpf_probe_read_kernel_str(dst, len, src);
		else
			err = bpf_probe_read_user_str(dst, len, src);
		len = err; /* len is meaningful only if successful */
	} else {
		if (len > args_max_sized_arg_sz) /* truncate, if necessary */
			len = args_max_sized_arg_sz;
		if (is_kernel_addr(src))
			err = bpf_probe_read_kernel(dst, len, src);
		else
			err = bpf_probe_read_user(dst, len, src);
	}

	if (err < 0) {
		dctx->arg_lens[arg_idx] = err;
		return;
	}

	*dctx->data_len += (len + 7) / 8 * 8;
	dctx->arg_lens[arg_idx] = len;
}

static __noinline void record_fnargs(void *ctx, struct session *sess, u32 func_id, u32 seq_id)
{
	struct rec_fnargs_capture *r;
	const struct func_info *fi;
	struct data_capture_ctx dctx;
	u64 i, rec_sz;

	/* we waste *args_max_any_arg_sz* + 12 * 8 (for raw ptrs value) to simplify verification */
	rec_sz = sizeof(*r) + args_max_total_args_sz + args_max_any_arg_sz + 8 * MAX_FNARGS_ARG_SPEC_CNT;
	r = bpf_ringbuf_reserve(&rb, rec_sz, 0);
	if (!r) {
		stat_dropped_record(sess);
		return;
	}

	r->type = REC_FNARGS_CAPTURE;
	r->sess_id = sess->sess_id;
	r->seq_id = seq_id;
	r->func_id = func_id;
	r->arg_ptrs = 0;
	r->data_len = 0;

	dctx.data = r->arg_data;
	dctx.data_len = &r->data_len;
	dctx.arg_lens = r->arg_lens;
	dctx.arg_ptrs = &r->arg_ptrs;

	fi = func_info(func_id);
	for (i = 0; i < MAX_FNARGS_ARG_SPEC_CNT; i++) {
		u32 spec = fi->arg_specs[i], reg_idx, off, kind, loc;
		u64 len = spec & FNARGS_LEN_MASK;
		void *data_ptr = NULL;
		u64 vals[2];
		int err;

		if (spec == 0)
			break;

		if (len == 0) {
			r->arg_lens[i] = 0;
			continue;
		}

		loc = (spec & FNARGS_LOC_MASK) >> FNARGS_LOC_SHIFT;
		kind = (spec & FNARGS_KIND_MASK) >> FNARGS_KIND_SHIFT;

		switch (loc) {
		case FNARGS_REG:
			reg_idx = (spec & FNARGS_REGIDX_MASK) >> FNARGS_REGIDX_SHIFT;
			vals[0] = get_arg_reg_value(ctx, reg_idx);
			if (kind != FNARGS_KIND_RAW) {
				data_ptr = (void *)vals[0];
			} else {
				vals[0] = coerce_size(vals[0], len);
				data_ptr = vals;
			}
			break;
		case FNARGS_STACK:
			/* stack offset is specified in 8 byte chunks */
			off = 8 * ((spec & FNARGS_STACKOFF_MASK) >> FNARGS_STACKOFF_SHIFT);
			vals[0] = get_stack_pointer(ctx) + off;
			if (kind != FNARGS_KIND_RAW) {
				/* the pointer value itself is on the stack */
				err = bpf_probe_read_kernel(&vals[0], 8, (void *)vals[0]);
				if (err) {
					r->arg_lens[i] = err;
					continue;
				}
			}
			data_ptr = (void *)vals[0];
			break;
		case FNARGS_REG_PAIR:
			/* there is no special kind besides FNARGS_KIND_RAW for REG_PAIR */
			reg_idx = (spec & FNARGS_REGIDX_MASK) >> FNARGS_REGIDX_SHIFT;
			vals[0] = get_arg_reg_value(ctx, reg_idx);
			vals[1] = get_arg_reg_value(ctx, reg_idx + 1);
			vals[1] = coerce_size(vals[1], len - 8);
			data_ptr = (void *)vals;
			break;
		default:
			r->arg_lens[i] = -EDOM;
			continue;
		}

		if (kind == FNARGS_KIND_VARARG) {
			capture_vararg(&dctx, i, data_ptr);
		} else {
			dctx.record_ptr = (kind == FNARGS_KIND_PTR) || (kind == FNARGS_KIND_STR);
			dctx.is_str = kind == FNARGS_KIND_STR;
			capture_arg(&dctx, i, data_ptr, len);
		}
	}

	bpf_ringbuf_submit(r, 0);
}

static __noinline void record_ctxargs(void *ctx, struct session *sess, u32 probe_id, u32 seq_id)
{
	struct rec_ctxargs_capture *r;
	const struct ctxargs_info *ci;
	struct data_capture_ctx dctx;
	u64 i, rec_sz;

	/* we waste *args_max_any_arg_sz* + 12 * 8 (for raw ptrs value) to simplify verification */
	rec_sz = sizeof(*r) + args_max_total_args_sz + args_max_any_arg_sz + 8 * MAX_CTXARGS_SPEC_CNT;
	r = bpf_ringbuf_reserve(&rb, rec_sz, 0);
	if (!r) {
		stat_dropped_record(sess);
		return;
	}

	r->type = REC_CTXARGS_CAPTURE;
	r->sess_id = sess->sess_id;
	r->seq_id = seq_id;
	r->probe_id = probe_id;
	r->ptrs_mask = 0;
	r->data_len = 0;

	dctx.data = r->data;
	dctx.data_len = &r->data_len;
	dctx.arg_lens = r->lens;
	dctx.arg_ptrs = &r->ptrs_mask;

	ci = ctxargs_info(probe_id);
	for (i = 0; i < MAX_CTXARGS_SPEC_CNT; i++) {
		u32 spec = ci->specs[i], off, kind;
		u64 len = spec & CTXARG_LEN_MASK;
		void *src_ptr = NULL;
		u32 loc;
		int err;

		if (spec == 0)
			break;

		if (len == 0) {
			r->lens[i] = 0;
			continue;
		}

		off = (spec & CTXARG_OFF_MASK) >> CTXARG_OFF_SHIFT;
		kind = (spec & CTXARG_KIND_MASK) >> CTXARG_KIND_SHIFT;

		switch (kind) {
		case CTXARG_KIND_VALUE:
			dctx.record_ptr = false;
			dctx.is_str = false;
			src_ptr = ctx + off;
			break;
		case CTXARG_KIND_PTR_FIXED:
		case CTXARG_KIND_PTR_STR:
			dctx.record_ptr = true;
			dctx.is_str = kind == CTXARG_KIND_PTR_STR;
			err = bpf_probe_read_kernel(&src_ptr, sizeof(src_ptr), ctx + off);
			if (err) {
				r->lens[i] = err;
				continue;
			}
			break;
		case CTXARG_KIND_TP_VARLEN:
			dctx.record_ptr = false;
			dctx.is_str = true; /* we assume string, we don't know any better */

			/* first, read u32 identifying where and how much data we have */
			err = bpf_probe_read_kernel(&loc, sizeof(loc), ctx + off);
			if (err) {
				r->lens[i] = err;
				continue;
			}

			/* loc's lower 16 bits are offset, upper 16 bits are size */
			src_ptr = ctx + (loc & 0xffff);
			if ((loc >> 16) < len)
				len = loc >> 16;
			break;
		default:
			r->lens[i] = -EDOM;
			continue;
		}

		capture_arg(&dctx, i, src_ptr, len);
	}

	bpf_ringbuf_submit(r, 0);
}

static bool is_call_stack_stitched(const struct session *sess)
{
	return sess->max_depth + 1 == sess->saved_depth;
}

static bool can_stitch_stacks(const struct session *sess)
{
	return sess->saved_depth && sess->max_depth + 1 == sess->saved_depth;
}

static __noinline void save_stitch_stack(void *ctx, struct session *sess)
{
	u64 d = sess->depth;
	u64 len = sess->max_depth - d;
	u64 kstack_sz, lbrs_sz;

	if (d >= MAX_FSTACK_DEPTH || len >= MAX_FSTACK_DEPTH) {
		log("SHOULDN'T HAPPEN DEPTH %ld LEN %ld", d, len);
		return;
	}

	dlog("CURRENT DEPTH %d..%d", sess->depth + 1, sess->max_depth);
	dlog("SAVED DEPTH %d..%d", sess->saved_depth, sess->saved_max_depth);

	/* we can stitch together stack subsections */
	if (can_stitch_stacks(sess)) {
		__memcpy(sess->saved_ids + d, sess->func_ids + d, len * sizeof(sess->saved_ids[0]));
		__memcpy(sess->saved_res + d, sess->func_res + d, len * sizeof(sess->saved_res[0]));
		__memcpy(sess->saved_lat + d, sess->func_lat + d, len * sizeof(sess->saved_lat[0]));
		__memcpy(sess->saved_seq_ids + d, sess->seq_ids + d, len * sizeof(sess->saved_seq_ids[0]));

		/* keep previously saved (deeper) kstack and lbrs */

		sess->saved_depth = sess->depth + 1;
		dlog("STITCHED STACK %d..%d to ..%d",
		     sess->depth + 1, sess->max_depth, sess->saved_max_depth);
		return;
	}

	dlog("RESETTING SAVED ERR STACK %d..%d to %d..",
	     sess->saved_depth, sess->saved_max_depth, sess->depth + 1);

	sess->saved_last_seq_id = sess->next_seq_id - 1;

	__memcpy(sess->saved_ids + d, sess->func_ids + d, len * sizeof(sess->saved_ids[0]));
	__memcpy(sess->saved_res + d, sess->func_res + d, len * sizeof(sess->saved_res[0]));
	__memcpy(sess->saved_lat + d, sess->func_lat + d, len * sizeof(sess->saved_lat[0]));
	__memcpy(sess->saved_seq_ids + d, sess->seq_ids + d, len * sizeof(sess->saved_seq_ids[0]));

	kstack_sz = sess->saved_kstack_sz = sess->kstack_sz;
	if (kstack_sz <= sizeof(sess->saved_kstack))
		__memcpy(sess->saved_kstack, sess->kstack, kstack_sz);

	if (use_lbr) {
		lbrs_sz = sess->saved_lbrs_sz = sess->lbrs_sz;
		if (lbrs_sz <= sizeof(sess->saved_lbrs))
			__memcpy(sess->saved_lbrs, sess->lbrs, lbrs_sz);
	}

	sess->saved_depth = sess->depth + 1;
	sess->saved_max_depth = sess->max_depth;
}

static const struct session empty_session;

static bool emit_session_start(struct session *sess)
{
	struct rec_session_start *r;

	r = bpf_ringbuf_reserve(&rb, sizeof(*r), 0);
	if (!r) {
		atomic_inc(&stats.dropped_sessions);
		return false;
	}

	r->type = REC_SESSION_START;
	r->sess_id = sess->sess_id;
	r->pid = sess->pid;
	r->tgid = sess->tgid;
	r->start_ts = sess->start_ts;
	__builtin_memcpy(r->task_comm, sess->task_comm, sizeof(sess->task_comm));
	__builtin_memcpy(r->proc_comm, sess->proc_comm, sizeof(sess->proc_comm));

	bpf_ringbuf_submit(r, 0);

	return true;
}

static __always_inline int session_id(int pid)
{
	return pid ?: -(1 + bpf_get_smp_processor_id());
}

static int submit_session(void *ctx, struct session *sess, enum session_type sess_type);

static bool should_submit_interim_stack(const struct session *sess)
{
	if (emit_success_stacks)
		return true;

	if (!sess->is_err)
		return false;

	if (sess->saved_depth > 0 && !can_stitch_stacks(sess))
		return true;

	return false;
}

static __noinline bool push_call_stack(void *ctx, u32 id, u64 ip)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = (u32)pid_tgid;
	struct session *sess;
	int seq_id, sess_id;
	u64 d;

	sess_id = session_id(pid);
	sess = bpf_map_lookup_elem(&sessions, &sess_id);
	if (!sess) {
		struct task_struct *tsk;

		if (!(func_info(id)->flags & FUNC_IS_ENTRY))
			return false;

		bpf_map_update_elem(&sessions, &sess_id, &empty_session, BPF_ANY);
		sess = bpf_map_lookup_elem(&sessions, &sess_id);
		if (!sess) {
			atomic_inc(&stats.dropped_sessions);
			return false;
		}

		sess->sess_id = sess_id;
		sess->pid = pid;
		sess->tgid = (u32)(pid_tgid >> 32);
		sess->start_ts = bpf_ktime_get_ns();
		bpf_get_current_comm(&sess->task_comm, sizeof(sess->task_comm));
		tsk = (void *)bpf_get_current_task();
		BPF_CORE_READ_INTO(&sess->proc_comm, tsk, group_leader, comm);

		if (emit_func_trace || capture_fn_args || capture_ctx_args) {
			if (!emit_session_start(sess)) {
				vlog("DEFUNCT SESSION %d TID/PID %d/%d: failed to send SESSION_START record!",
				     sess->sess_id, sess->pid, sess->tgid);
				sess->defunct = true;
				goto out_defunct;
			} else {
				sess->start_emitted = true;
			}
		}
	}

	/* if we failed to send out REC_SESSION_START, update depth and bail */
	if (sess->defunct) {
out_defunct:
		sess->depth++;
		return false;
	}

	d = sess->depth;
	barrier_var(d);
	if (d >= MAX_FSTACK_DEPTH)
		return false;

	if (sess->depth != sess->max_depth) {
		/* This is the point where we might lose information that we
		 * so far collected. As such, if interim stacks are enabled,
		 * we need to make a decision whether we need to emit useful
		 * interim stack. If we have error stack and it can be
		 * stitched, though, then we postpone emitting it unnecessarily,
		 * given we preserve all the relevant information.
		 */
		if (emit_interim_stacks && should_submit_interim_stack(sess))
			submit_session(ctx, sess, SESSION_STITCH);
		if (sess->defunct)
			goto out_defunct;
		if (sess->is_err)
			save_stitch_stack(ctx, sess);
	}

	seq_id = sess->next_seq_id;
	sess->next_seq_id++;

	sess->func_ids[d] = id;
	sess->seq_ids[d] = seq_id;
	sess->is_err = false;
	sess->depth = d + 1;
	sess->max_depth = d + 1;
	sess->func_lat[d] = bpf_ktime_get_ns();

	if (emit_func_trace) {
		struct rec_func_trace_entry *fe;

		fe = bpf_ringbuf_reserve(&rb, sizeof(*fe), 0);
		if (!fe) {
			stat_dropped_record(sess);
			goto skip_ft_entry;
		}

		fe->type = REC_FUNC_TRACE_ENTRY;
		fe->ts = bpf_ktime_get_ns();
		fe->sess_id = sess_id;
		fe->seq_id = seq_id;
		fe->depth = d + 1;
		fe->func_id = id;
		fe->func_lat = 0;
		fe->func_res = 0;

		bpf_ringbuf_submit(fe, 0);
skip_ft_entry:;
	}

	if (capture_fn_args)
		record_fnargs(ctx, sess, id, seq_id);

	if (verbose) {
		const char *func_name = func_info(id)->name;

		if (printk_is_sane) {
			if (d == 0)
				log("=== STARTING TRACING %s [COMM %s SESS %d] ===",
				    func_name, sess->task_comm, sess_id);
			log("    ENTER %s%s [...]", spaces + 2 * ((255 - d) & 0xFF), func_name);
		} else {
			if (d == 0) {
				log("=== STARTING TRACING %s [SESS %d] ===", func_name, sess_id);
				log("=== ...      TRACING [SESS %d COMM %s] ===", sess_id, sess->task_comm);
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

	sess->is_err = false;
	sess->saved_depth = 0;
	sess->saved_max_depth = 0;
	sess->depth = 0;
	sess->max_depth = 0;
	sess->kstack_sz = 0;
	sess->next_seq_id = 0;

	sess->lbrs_sz = 0;
}

static void copy_stack_trace(void *ctx, struct rec_session_end *r,
			     const struct session *sess, enum session_type sess_type)
{
	u64 kstack_sz;
	const long *kstack;

	if (sess_type == SESSION_PROBE) {
		r->stack.kstack_sz = bpf_get_stack(ctx, r->stack.kstack, sizeof(r->stack.kstack), 0);
		return;
	}

	if (sess_type == SESSION_STITCH || is_call_stack_stitched(sess)) {
		kstack_sz = sess->saved_kstack_sz;
		kstack = sess->saved_kstack;
	} else {
		kstack_sz = sess->kstack_sz;
		kstack = sess->kstack;
	}

	r->stack.kstack_sz = kstack_sz;
	if (kstack_sz <= sizeof(r->stack.kstack))
		__memcpy(r->stack.kstack, kstack, kstack_sz);
}

static void copy_call_stack(struct rec_session_end *r, const struct session *sess,
			    enum session_type sess_type)
{
	u64 d, len;

	len = sess->max_depth;
	if (len >= MAX_FSTACK_DEPTH)
		return; /* can't happen */

	r->stack.depth = sess->depth;
	r->stack.max_depth = sess->max_depth;
	r->stack.stitch_pos = 0;

	__memcpy(r->stack.func_ids, &sess->func_ids, len * sizeof(sess->func_ids[0]));
	__memcpy(r->stack.seq_ids, &sess->seq_ids, len * sizeof(sess->seq_ids[0]));
	__memcpy(r->stack.func_res, &sess->func_res, len * sizeof(sess->func_res[0]));
	__memcpy(r->stack.func_lat, &sess->func_lat, len * sizeof(sess->func_lat[0]));

	/* don't stitch anything for inject probe interim stack */
	if (sess_type == SESSION_PROBE)
		return;

	if (sess_type == SESSION_STITCH || is_call_stack_stitched(sess)) {
		d = sess->saved_depth - 1;
		len = sess->saved_max_depth - d;

		if (d >= MAX_FSTACK_DEPTH || len >= MAX_FSTACK_DEPTH) {
			log("SHOULDN'T HAPPEN DEPTH %ld LEN %ld", d, len);
			return;
		}

		r->stack.max_depth = sess->saved_max_depth;
		r->stack.stitch_pos = d;

		__memcpy(r->stack.func_ids + d, sess->saved_ids + d, len * sizeof(sess->func_ids[0]));
		__memcpy(r->stack.seq_ids + d, sess->saved_seq_ids + d, len * sizeof(sess->seq_ids[0]));
		__memcpy(r->stack.func_res + d, sess->saved_res + d, len * sizeof(sess->func_res[0]));
		__memcpy(r->stack.func_lat + d, sess->saved_lat + d, len * sizeof(sess->func_lat[0]));
	}
}

static int submit_session(void *ctx, struct session *sess, enum session_type sess_type)
{
	bool emit_session, final_session;
	u64 emit_ts = bpf_ktime_get_ns();

	final_session = sess_type == SESSION_FINAL;
	emit_session = sess->is_err || emit_success_stacks || sess_type == SESSION_PROBE;

	if (duration_ns) {
		/* In final session, func_lat[0] is finalized already and
		 * represents overall session duration.
		 * But for interim sessions, func_lat[0] is a timestamp of
		 * session start, so we can calculate session duration
		 * *so far* using (emit_ts - sess->func_lat[0]) difference.
		 */
		if (final_session && sess->func_lat[0] < duration_ns)
			emit_session = false;
		else if (!final_session && emit_ts - sess->func_lat[0] < duration_ns)
			emit_session = false;
	}

	if (emit_session) {
		dlog("EMIT %s STACK DEPTH %d (SAVED ..%d)",
		     sess->is_err ? "ERROR" : "SUCCESS",
		     sess->max_depth, sess->saved_max_depth);
	}

	if (emit_session && !sess->start_emitted) {
		if (!emit_session_start(sess)) {
			vlog("DEFUNCT SESSION %d TID/PID %d/%d: failed to send SESSION data!",
			     sess->sess_id, sess->pid, sess->tgid);
			sess->defunct = true;
			return -EINVAL;
		}
		sess->start_emitted = true;
	}

	if (emit_session && use_lbr) {
		struct rec_lbr_stack *r;

		r = bpf_ringbuf_reserve(&rb, sizeof(*r), 0);
		if (!r) {
			/* record that we failed to submit LBR data */
			stat_dropped_record(sess);
			sess->lbrs_sz = -ENOSPC;
			goto skip_lbrs;
		}

		r->type = REC_LBR_STACK;
		r->sess_id = sess->sess_id;
		switch (sess_type) {
		case SESSION_PROBE:
			/* for injected probe, take current LBR */
			r->lbrs_sz = copy_lbrs(r->lbrs, sizeof(r->lbrs));
			break;
		case SESSION_STITCH:
			/* for stitched stack, we already saved earlier LBR */
			r->lbrs_sz = sess->saved_lbrs_sz;
			__memcpy(r->lbrs, sess->saved_lbrs, sizeof(sess->saved_lbrs));
			break;
		case SESSION_FINAL:
		default:
			if (is_call_stack_stitched(sess)) {
				r->lbrs_sz = sess->saved_lbrs_sz;
				__memcpy(r->lbrs, sess->saved_lbrs, sizeof(sess->saved_lbrs));
			} else {
				r->lbrs_sz = sess->lbrs_sz;
				__memcpy(r->lbrs, sess->lbrs, sizeof(sess->lbrs));
			}
		}

		bpf_ringbuf_submit(r, 0);
skip_lbrs:;
	}

	if (emit_session || (final_session && sess->start_emitted)) {
		struct rec_session_end *r;

		r = bpf_ringbuf_reserve(&rb, sizeof(*r), 0);
		if (!r) {
			atomic_inc(&stats.dropped_sessions);
			return -EINVAL;
		}

		switch (sess_type) {
		case SESSION_PROBE:
			r->type = REC_SESSION_PROBE;
			r->last_seq_id = sess->next_seq_id - 1;
			break;
		case SESSION_STITCH:
			r->type = REC_SESSION_STITCH;
			r->last_seq_id = sess->saved_last_seq_id;
			break;
		case SESSION_FINAL:
		default:
			r->type = REC_SESSION_END;
			r->last_seq_id = sess->next_seq_id - 1;
			break;
		}
		r->sess_id = sess->sess_id;
		r->emit_ts = emit_ts;
		r->ignored = !emit_session;
		r->is_err = sess->is_err;
		r->lbrs_sz = sess->lbrs_sz;
		r->dropped_records = sess->dropped_records;

		/* copy over STACK_TRACE "record", if required */
		if (emit_session) {
			copy_stack_trace(ctx, r, sess, sess_type);
			copy_call_stack(r, sess, sess_type);
		}

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
	int seq_id, sess_id;

	pid = (u32)bpf_get_current_pid_tgid();
	sess_id = session_id(pid);
	sess = bpf_map_lookup_elem(&sessions, &sess_id);
	if (!sess)
		return false;

	/* if we failed to send out REC_SESSION_START, clean up and send nothing else */
	if (sess->defunct) {
		sess->depth--;
		if (sess->depth == 0) {
			reset_session(sess);
			bpf_map_delete_elem(&sessions, &sess_id);
			vlog("DEFUNCT SESSION %d TID/PID %d/%d: SESSION_END, no data was collected!",
			     sess_id, pid, sess->tgid);
		}
		return false;
	}

	seq_id = sess->next_seq_id;
	sess->next_seq_id++;

	d = sess->depth;
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

	lat = bpf_ktime_get_ns() - sess->func_lat[d];

	if (emit_func_trace) {
		struct rec_func_trace_entry *fe;

		fe = bpf_ringbuf_reserve(&rb, sizeof(*fe), 0);
		if (!fe) {
			stat_dropped_record(sess);
			goto skip_ft_exit;
		}

		fe->type = REC_FUNC_TRACE_EXIT;
		fe->ts = bpf_ktime_get_ns();
		fe->sess_id = sess_id;
		fe->seq_id = seq_id;
		fe->depth = d + 1;
		fe->func_id = id;
		fe->func_lat = lat;
		fe->func_res = res;

		bpf_ringbuf_submit(fe, 0);
skip_ft_exit:;
	}
	if (verbose)
		print_exit(ctx, d, id, res);

	exp_id = sess->func_ids[d];
	if (exp_id != id) {
		const struct func_info *exp_fi = func_info(exp_id);

		vlog("POP(0) UNEXPECTED PID %d DEPTH %d MAX DEPTH %d",
		     pid, sess->depth, sess->max_depth);
		vlog("POP(1) UNEXPECTED GOT  ID %d ADDR %lx NAME %s",
		     id, ip, func_name);
		vlog("POP(2) UNEXPECTED WANT ID %u ADDR %lx NAME %s",
		     exp_id, exp_fi->ip, exp_fi->name);

		atomic_inc(&stats.dropped_sessions);
		reset_session(sess);
		bpf_map_delete_elem(&sessions, &sess_id);

		return false;
	}

	sess->func_res[d] = res;
	sess->func_lat[d] = lat;

	/* unmark stack as errored if any of return functions succeeded
	 * (except for void functions, in which case just preserve original
	 * error mark, if any
	 */
	if (!(flags & FUNC_CANT_FAIL) && !failed)
		sess->is_err = false;

	if (failed && !sess->is_err) {
		sess->is_err = true;
		sess->max_depth = d + 1;
		sess->kstack_sz = bpf_get_stack(ctx, &sess->kstack, sizeof(sess->kstack), 0);
		sess->lbrs_sz = copy_lbrs(sess->lbrs, sizeof(sess->lbrs));
	} else if (emit_success_stacks && d + 1 == sess->max_depth) {
		sess->kstack_sz = bpf_get_stack(ctx, &sess->kstack, sizeof(sess->kstack), 0);
		sess->lbrs_sz = copy_lbrs(sess->lbrs, sizeof(sess->lbrs));
	}
	sess->depth = d;

	/* emit last complete stack trace */
	if (d == 0) {
		/* can fail or do nothing for current session */
		submit_session(ctx, sess, SESSION_FINAL);

		reset_session(sess);
		bpf_map_delete_elem(&sessions, &sess_id);
	}

	return true;
}

static void handle_inj_probe(void *ctx, u32 id)
{
	struct session *sess;
	int seq_id, sess_id, err;
	u32 pid;

	pid = (u32)bpf_get_current_pid_tgid();
	sess_id = session_id(pid);
	sess = bpf_map_lookup_elem(&sessions, &sess_id);
	if (!sess || sess->defunct)
		return;

	seq_id = sess->next_seq_id;
	sess->next_seq_id++;

	if (emit_func_trace) {
		struct rec_inj_probe *r;

		r = bpf_ringbuf_reserve(&rb, sizeof(*r), 0);
		if (!r) {
			stat_dropped_record(sess);
			return;
		}

		r->type = REC_INJ_PROBE;
		r->ts = bpf_ktime_get_ns();
		r->sess_id = sess_id;
		r->seq_id = seq_id;
		r->probe_id = id;
		r->depth = sess->depth + 1;

		bpf_ringbuf_submit(r, 0);
	}

	if (emit_func_trace && capture_ctx_args)
		record_ctxargs(ctx, sess, id, seq_id);

	/* for now, in --interim-stacks (-I) mode we'll emit interim stacks
	 * for each injected probe; we may want to revisit this behavior
	 * later, but for now that's the most straightforward way to actually
	 * see LBR with each kprobe/tracepoint of interest, if necessary
	 */
	if (emit_interim_stacks)
		submit_session(ctx, sess, SESSION_PROBE);
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

__hidden int handle_inj_kprobe(struct pt_regs *ctx, u32 probe_id)
{
	handle_inj_probe(ctx, probe_id);
	return 0;
}

__hidden int handle_inj_kretprobe(struct pt_regs *ctx, u32 probe_id)
{
	handle_inj_probe(ctx, probe_id);
	return 0;
}

__hidden int handle_inj_rawtp(void *ctx, u32 probe_id)
{
	handle_inj_probe(ctx, probe_id);
	return 0;
}

__hidden int handle_inj_tp(void *ctx, u32 probe_id)
{
	handle_inj_probe(ctx, probe_id);
	return 0;
}
