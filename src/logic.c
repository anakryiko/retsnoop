// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2024 Meta Platforms, Inc. */
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <bpf/btf.h>
#include <linux/perf_event.h>
#include "retsnoop.h"
#include "logic.h"
#include "env.h"
#include "ksyms.h"
#include "addr2line.h"
#include "mass_attacher.h"
#include "utils.h"
#include "hashmap.h"

static size_t session_hasher(long key, void *ctx)
{
	return (size_t)key;
}

static bool session_equals(long key1, long key2, void *ctx)
{
	return key1 == key2;
}

static struct hashmap sessions_hash = HASHMAP_INIT(session_hasher, session_equals, NULL);

static void free_session(struct session *sess)
{
	int i;

	if (!sess)
		return;

	for (i = 0; i < sess->fn_args_cnt; i++) {
		free(sess->fn_args_entries[i].arg_data);
	}
	free(sess->fn_args_entries);

	free(sess->lbrs);

	free(sess->ft_entries);
	free(sess);
}

static void free_sessions(void)
{
	struct hashmap_entry *e;
	int bkt;

	hashmap__for_each_entry(&sessions_hash, e, bkt) {
		free_session(e->pvalue);
	}

	hashmap__clear(&sessions_hash);
}

static void purge_session(struct ctx *ctx, int pid)
{
	struct session *sess;

	if (hashmap__delete(&sessions_hash, (long)pid, NULL, &sess))
		free_session(sess);
}

static int handle_session_start(struct ctx *ctx, const struct session_start *r)
{
	struct session *sess;

	purge_session(ctx, r->pid);

	sess = calloc(1, sizeof(*sess));
	if (!sess || hashmap__add(&sessions_hash, (long)r->pid, sess)) {
		fprintf(stderr, "Failed to allocate memory for session PID %d!\n", r->pid);
		return -ENOMEM;
	}

	sess->pid = r->pid;
	sess->tgid = r->tgid;
	sess->start_ts = r->start_ts;
	memcpy(sess->proc_comm, r->proc_comm, sizeof(r->proc_comm));
	memcpy(sess->task_comm, r->task_comm, sizeof(r->task_comm));

	return 0;
}

static int handle_lbr_stack(struct ctx *dctx, struct session *sess, const struct lbr_stack *r)
{
	if (sess->lbrs) {
		fprintf(stderr, "BUG: PID %d session data contains LBR data already!\n", r->pid);
		return -EINVAL;
	}

	sess->lbrs_sz = r->lbrs_sz;

	if (sess->lbrs_sz > 0) {
		sess->lbrs = malloc(sess->lbrs_sz);
		if (!sess->lbrs) {
			fprintf(stderr, "SESSION PID %d: failed to allocate LBR memory: %d\n", r->pid, -ENOMEM);
			return -ENOMEM;
		}
		memcpy(sess->lbrs, r->lbrs, sess->lbrs_sz);
	}

	return 0;
}

static char underline[512]; /* fill be filled with header underline char */
static char spaces[512]; /* fill be filled with spaces */

/* logical stack trace item */
struct fstack_item {
	const struct mass_attacher_func_info *finfo;
	int flags;
	const char *name;
	long res;
	long lat;
	bool finished;
	bool stitched;
	bool err_start;
};

static bool should_report_stack(struct ctx *ctx, const struct call_stack *s)
{
	int i, id, flags, res;
	bool allowed = false;

	if (!env.has_error_filter)
		return true;

	for (i = 0; i < s->max_depth; i++) {
		id = s->func_ids[i];
		flags = func_info(ctx, id)->flags;

		if (flags & FUNC_CANT_FAIL)
			continue;

		res = s->func_res[i];
		if (flags & FUNC_NEEDS_SIGN_EXT)
			res = (long)(int)res;

		if (res == 0 && !(flags & FUNC_RET_PTR))
			continue;

		/* if error is blacklisted, reject immediately */
		if (is_err_in_mask(env.deny_error_mask, res))
			return false;
		/* if error is whitelisted, mark as allowed; but we need to
		 * still see if any other errors in the stack are blacklisted
		 */
		if (is_err_in_mask(env.allow_error_mask, res))
			allowed = true;
	}

	/* no stitched together stack */
	if (s->max_depth + 1 != s->saved_depth)
		return allowed;

	for (i = s->saved_depth - 1; i < s->saved_max_depth; i++) {
		id = s->saved_ids[i];
		flags = func_info(ctx, id)->flags;

		if (flags & FUNC_CANT_FAIL)
			continue;

		res = s->func_res[i];
		if (flags & FUNC_NEEDS_SIGN_EXT)
			res = (long)(int)res;

		if (res == 0 && !(flags & FUNC_RET_PTR))
			continue;

		/* if error is blacklisted, reject immediately */
		if (is_err_in_mask(env.deny_error_mask, res))
			return false;
		/* if error is whitelisted, mark as allowed; but we need to
		 * still see if any other errors in the stack are blacklisted
		 */
		if (is_err_in_mask(env.allow_error_mask, res))
			allowed = true;
	}

	return allowed;
}

static int filter_fstack(struct ctx *ctx, struct fstack_item *r, const struct call_stack *s)
{
	const struct mass_attacher_func_info *finfo;
	struct mass_attacher *att = ctx->att;
	struct fstack_item *fitem;
	const char *fname;
	int i, id, flags, cnt;

	for (i = 0, cnt = 0; i < s->max_depth; i++, cnt++) {
		id = s->func_ids[i];
		flags = func_info(ctx, id)->flags;
		finfo = mass_attacher__func(att, id);
		fname = finfo->name;

		fitem = &r[cnt];
		fitem->finfo = finfo;
		fitem->flags = flags;
		fitem->name = fname;
		fitem->stitched = false;
		if (i >= s->depth) {
			fitem->finished = true;
			fitem->lat = s->func_lat[i];
		} else {
			fitem->finished = false;
			fitem->lat = 0;
		}
		if (flags & FUNC_NEEDS_SIGN_EXT)
			fitem->res = (long)(int)s->func_res[i];
		else
			fitem->res = s->func_res[i];
		fitem->lat = s->func_lat[i];
	}

	/* no stitched together stack */
	if (s->max_depth + 1 != s->saved_depth)
		return cnt;

	for (i = s->saved_depth - 1; i < s->saved_max_depth; i++, cnt++) {
		id = s->saved_ids[i];
		flags = func_info(ctx, id)->flags;
		finfo = mass_attacher__func(att, id);
		fname = finfo->name;

		fitem = &r[cnt];
		fitem->finfo = finfo;
		fitem->flags = flags;
		fitem->name = fname;
		fitem->stitched = true;
		fitem->finished = true;
		fitem->lat = s->saved_lat[i];
		if (flags & FUNC_NEEDS_SIGN_EXT)
			fitem->res = (long)(int)s->saved_res[i];
		else
			fitem->res = s->saved_res[i];
	}

	return cnt;
}

/* actual kernel stack trace item */
struct kstack_item {
	const struct ksym *ksym;
	long addr;
	bool filtered;
};

static bool is_bpf_tramp(const struct kstack_item *item)
{
	static char bpf_tramp_pfx[] = "bpf_trampoline_";

	if (!item->ksym)
		return false;

	return strncmp(item->ksym->name, bpf_tramp_pfx, sizeof(bpf_tramp_pfx) - 1) == 0
	       && isdigit(item->ksym->name[sizeof(bpf_tramp_pfx)]);
}

/* recognize stack trace entries representing BPF program, e.g.:
 * bpf_prog_28efb01f5c962284_my_prog
 */
static bool is_bpf_prog(const struct kstack_item *item)
{
	static char bpf_prog_pfx[] = "bpf_prog_";
	const char *s;
	int i;
	bool has_digits = false;

	if (!item->ksym)
		return false;

	s = item->ksym->name;
	if (strncmp(s, bpf_prog_pfx, sizeof(bpf_prog_pfx) - 1) != 0)
		return false;

	for (i = sizeof(bpf_prog_pfx); s[i] && s[i] != '_'; i++ ) {
		if (!isxdigit(s[i]))
			return false;

		if (isdigit(s[i]))
			has_digits = true;
	}

	return has_digits;
}

#define FTRACE_OFFSET 0x5

static int filter_kstack(struct ctx *ctx, struct kstack_item *r, const struct call_stack *s)
{
	struct ksyms *ksyms = ctx->ksyms;
	int i, n, p;

	/* lookup ksyms and reverse stack trace to match natural call order */
	n = s->kstack_sz / 8;
	for (i = 0; i < n; i++) {
		struct kstack_item *item = &r[n - i - 1];

		item->addr = s->kstack[i];
		item->filtered = false;
		item->ksym = ksyms__map_addr(ksyms, item->addr);
		if (!item->ksym)
			continue;
	}

	/* perform addiitonal post-processing to filter out bpf_trampoline and
	 * bpf_prog symbols, fixup fexit patterns, etc
	 */
	for (i = 0, p = 0; i < n; i++) {
		struct kstack_item *item = &r[p];

		*item = r[i];

		if (!item->ksym) {
			p++;
			continue;
		}

		/* Ignore bpf_trampoline frames and fix up stack traces.
		 * When fexit program happens to be inside the stack trace,
		 * a following stack trace pattern will be apparent (taking
		 * into account inverted order of frames * which we did few
		 * lines above):
		 *     ffffffff8116a3d5 bpf_map_alloc_percpu+0x5
		 *     ffffffffa16db06d bpf_trampoline_6442494949_0+0x6d
		 *     ffffffff8116a40f bpf_map_alloc_percpu+0x3f
		 * 
		 * bpf_map_alloc_percpu+0x5 is real, by it just calls into the
		 * trampoline, which them calls into original call
		 * (bpf_map_alloc_percpu+0x3f). So the last item is what
		 * really matters, everything else is just a distraction, so
		 * try to detect this and filter it out. Unless we are in
		 * full-stacks mode, of course, in which case we live a hint
		 * that this would be filtered out (helps with debugging
		 * overall), but otherwise is preserved.
		 */
		if (i + 2 < n && is_bpf_tramp(&r[i + 1])
		    && r[i].ksym == r[i + 2].ksym
		    && r[i].addr - r[i].ksym->addr == FTRACE_OFFSET) {
			if (env.stack_emit_all) {
				item->filtered = true;
				p++;
				continue;
			}

			/* skip two elements and process useful item */
			*item = r[i + 2];
			continue;
		}

		/* Ignore bpf_trampoline and bpf_prog in stack trace, those
		 * are most probably part of our own instrumentation, but if
		 * not, you can still see them in full-stacks mode.
		 * Similarly, remove bpf_get_stack_raw_tp, which seems to be
		 * always there due to call to bpf_get_stack() from BPF
		 * program.
		 */
		if (is_bpf_tramp(&r[i]) || is_bpf_prog(&r[i])
		    || strcmp(r[i].ksym->name, "bpf_get_stack_raw_tp") == 0) {
			if (env.stack_emit_all) {
				item->filtered = true;
				p++;
				continue;
			}

			if (i + 1 < n)
				*item = r[i + 1];
			continue;
		}

		p++;
	}

	return p;
}

static int detect_linux_src_loc(const char *path)
{
	static const char *linux_dirs[] = {
		"arch/", "block/", "certs/", "crypto/", "drivers/", "fs/",
		"include/", "init/", "io_uring/", "ipc/", "kernel/", "lib/",
		"mm/", "net/", "rust/", "scripts/", "security/", "sound/",
		"tools/", "usr/", "virt/",
	};
	int i;
	char *p;

	for (i = 0; i < ARRAY_SIZE(linux_dirs); i++) {
		p = strstr(path, linux_dirs[i]);
		if (p)
			return p - path;
	}

	return 0;
}

/* strip out column number in "kernel/bpf/syscall.c:5670:1" */
static void strip_out_column_num(char *file_linenum)
{
	int off1, off2, n, col;

	n = sscanf(file_linenum, "%*[^:]:%*d%n:%d%n", &off1, &col, &off2);
	/* sscanf doesn't report %n "matches" */
	if (n != 1)
		return;
	n = strlen(file_linenum);
	if (off2 != n)
		return;
	file_linenum[off1] = '\0';
}

struct stack_items_cache
{
	struct stack_item *items;
	size_t cnt;
	size_t cap;
};

static struct stack_items_cache stack_items1, stack_items2;

static struct stack_item *get_stack_item(struct stack_items_cache *cache)
{
	struct stack_item *s;

	if (cache->cnt == cache->cap) {
		size_t new_cap = cache->cap * 3 / 2;
		void *tmp;

		if (new_cap < 32)
			new_cap = 32;

		tmp = realloc(cache->items, new_cap * sizeof(*s));
		if (!tmp)
			return NULL;

		cache->items = tmp;
		memset(cache->items + cache->cap, 0, (new_cap - cache->cap) * sizeof(*s));
		cache->cap = new_cap;
	}

	s = &cache->items[cache->cnt++];

	s->dur_len = s->err_len = s->sym_len = s->src_len = 0;
	s->dur[0] = s->err[0] = s->sym[0] = s->src[0] = 0;
	s->marks[0] = s->marks[1] = ' ';

	return s;
}

int func_flags(const char *func_name, const struct btf *btf, int btf_id)
{
	const struct btf_type *t;

	if (!btf_id) {
		/* for kprobes-only functions we might not have BTF info,
		 * so assume int-returning failing function as the most common
		 * case
		 */
		return FUNC_NEEDS_SIGN_EXT;
	}

	/* FUNC */
	t = btf__type_by_id(btf, btf_id);

	/* FUNC_PROTO */
	t = btf__type_by_id(btf, t->type);

	/* check FUNC_PROTO's return type for VOID */
	if (!t->type)
		return FUNC_CANT_FAIL | FUNC_RET_VOID;

	t = btf__type_by_id(btf, t->type);
	while (btf_is_mod(t) || btf_is_typedef(t))
		t = btf__type_by_id(btf, t->type);

	if (btf_is_ptr(t))
		return FUNC_RET_PTR; /* can fail, no sign extension */

	/* unsigned is treated as non-failing */
	if (btf_is_int(t)) {
		if (btf_int_encoding(t) & BTF_INT_BOOL)
			return FUNC_CANT_FAIL | FUNC_RET_BOOL;
		if (!(btf_int_encoding(t) & BTF_INT_SIGNED))
			return FUNC_CANT_FAIL;
	}

	/* byte and word are treated as non-failing */
	if (t->size < 4)
		return FUNC_CANT_FAIL;

	/* integers need sign extension */
	if (t->size == 4)
		return FUNC_NEEDS_SIGN_EXT;

	return 0;
}

void format_func_flags(char *buf, size_t buf_sz, enum func_flags flags)
{
	char s[256];
	size_t s_len = 0;

	if (flags & FUNC_IS_ENTRY) {
		snappendf(s, "%sENTRY", s_len ? "|" : "");
		flags &= ~FUNC_IS_ENTRY;
	}
	if (flags & FUNC_CANT_FAIL) {
		snappendf(s, "%sNOFAIL", s_len ? "|" : "");
		flags &= ~FUNC_CANT_FAIL;
	}
	if (flags & FUNC_NEEDS_SIGN_EXT) {
		snappendf(s, "%sSIGNEXT", s_len ? "|" : "");
		flags &= ~FUNC_NEEDS_SIGN_EXT;
	}
	if (flags & FUNC_RET_PTR) {
		snappendf(s, "%sPTR", s_len ? "|" : "");
		flags &= ~FUNC_RET_PTR;
	}
	if (flags & FUNC_RET_BOOL) {
		snappendf(s, "%sBOOL", s_len ? "|" : "");
		flags &= ~FUNC_RET_BOOL;
	}
	if (flags & FUNC_RET_VOID) {
		snappendf(s, "%sVOID", s_len ? "|" : "");
		flags &= ~FUNC_RET_VOID;
	}
	if (flags)
		snappendf(s, "%s0x%x", s_len ? "|" : "", flags);

	snprintf(buf, buf_sz, "%s", s);
}

static void prepare_func_res(struct stack_item *s, long res, enum func_flags func_flags)
{
	const char *errstr;

	if (func_flags & FUNC_RET_VOID) {
		snappendf(s->err, "[void]");
		return;
	}

	if (func_flags & FUNC_NEEDS_SIGN_EXT)
		res = (long)(int)res;

	if (res >= 0 || res < -MAX_ERRNO) {
		if (func_flags & FUNC_RET_PTR)
			snappendf(s->err, res == 0 ? "[NULL]" : "[%p]", (const void *)res);
		else if (func_flags & FUNC_RET_BOOL)
			snappendf(s->err, res == 0 ? "[false]" : "[true]");
		else if (res >= -1024 * 1024 * 1024  && res < 1024 * 1024 /* random heuristic */)
			snappendf(s->err, "[%ld]", res);
		else
			snappendf(s->err, "[0x%lx]", res);
	} else {
		errstr = err_to_str(res);
		if (errstr)
			snappendf(s->err, "[-%s]", errstr);
		else
			snappendf(s->err, "[%ld]", res);
	}
}

static int handle_func_trace_entry(struct ctx *ctx, struct session *sess,
				   const struct func_trace_entry *r)
{
	struct func_trace_item *fti;
	void *tmp;

	tmp = realloc(sess->ft_entries, (sess->ft_cnt + 1) * sizeof(sess->ft_entries[0]));
	if (!tmp)
		return -ENOMEM;
	sess->ft_entries = tmp;

	fti = &sess->ft_entries[sess->ft_cnt];
	fti->ts = r->ts;
	fti->func_id = r->func_id;
	fti->depth = r->type == REC_FUNC_TRACE_ENTRY ? r->depth : -r->depth;
	fti->seq_id = r->seq_id;
	fti->func_lat = r->func_lat;
	fti->func_res = r->func_res;

	sess->ft_cnt++;

	return 0;
}

static void add_missing_records_msg(struct stack_items_cache *cache, int miss_cnt)
{
	struct stack_item *s;

	s = get_stack_item(cache);
	if (!s) {
		fprintf(stderr, "Ran out of formatting space, some data will be omitted!\n");
		return;
	}

	snappendf(s->src, "\u203C ... missing %d record%s ...",
		  miss_cnt, miss_cnt == 1 ? "" : "s");
	snappendf(s->dur, "...");
	snappendf(s->err, "...");
}

#define FNARGS_MISSING_RECORD (void *)-1000

static void prepare_ft_items(struct ctx *ctx, struct stack_items_cache *cache,
			     int pid, int last_seq_id)
{
	const struct mass_attacher_func_info *finfo;
	const char *sp, *mark;
	struct stack_item *s;
	struct session *sess;
	struct func_trace_item *f, *fn;
	int i, d, prev_seq_id = -1, orig_seq_id;
	int args_idx = 0;

	if (!hashmap__find(&sessions_hash, (long)pid, &sess))
		return;

	cache->cnt = 0;

	for (i = 0; i < sess->ft_cnt; prev_seq_id = f->seq_id, i++) {
		f = &sess->ft_entries[i];
		finfo = mass_attacher__func(ctx->att, f->func_id);
		d = f->depth > 0 ? f->depth : -f->depth;
		sp = spaces + sizeof(spaces) - 1 - 4 * min(d - 1, 20);

		if (f->seq_id > prev_seq_id + 1)
			add_missing_records_msg(cache, f->seq_id - prev_seq_id - 1);

		s = get_stack_item(cache);
		if (!s) {
			fprintf(stderr, "Ran out of formatting space, some data will be omitted!\n");
			break;
		}

		/* see if we can collapse leaf function entry/exit into one */
		orig_seq_id = f->seq_id;
		fn = &sess->ft_entries[i + 1];
		if (i + 1 < sess->ft_cnt &&
		    fn->seq_id == f->seq_id + 1 && /* consecutive items */
		    fn->func_id == f->func_id && /* same function */
		    f->depth > 0 && f->depth == -fn->depth /* matching entry and exit */) {
			f = fn; /* use exit item as main data source */
			i += 1; /* skip exit entry */
		}

		if (f == fn)		  /* collapsed leaf */
			mark = "\u2194 "; /* unicode <-> character */
		else if (f->depth > 0)	  /* entry */
			mark = "\u2192 "; /* unicode -> character */
		else			  /* exit */
			mark = "\u2190 "; /* unicode <- character */

		/* store function name and space indentation in sym, it should
		 * be enough even with deep nestedness levels (we cap them)
		 */
		snappendf(s->sym, "%s%s%s", sp, mark, finfo->name);

		if (f->depth < 0) {
			snappendf(s->dur, "%.3fus", f->func_lat / 1000.0);
			prepare_func_res(s, f->func_res, func_info(ctx, f->func_id)->flags);
		}

		if (env.capture_args) {
			struct func_args_item *fai = NULL;
			bool args_found = false;

			while (args_idx < sess->fn_args_cnt) {
				fai = &sess->fn_args_entries[args_idx];
				if (fai->seq_id > orig_seq_id)
					break;
				/* advance regardless if we found a match or not */
				args_idx++;
				if (fai->seq_id == orig_seq_id) {
					args_found = true;
					break;
				}
			}

			if (args_found)
				s->extra = fai;
			else if (f->depth > 0) /* func entry */
				s->extra = FNARGS_MISSING_RECORD;
			else
				s->extra = NULL;
		}
	}

	if (last_seq_id != prev_seq_id)
		add_missing_records_msg(cache, last_seq_id - prev_seq_id);
}

static void print_ft_items(struct ctx *ctx, const struct stack_items_cache *cache)
{
	int dur_len = 5, res_len = 0, sym_len = 0, arg_len = 0, i;
	struct stack_item *s;

	printf("\n");

	/* calculate desired length of each auto-sized part of the output */
	for (i = 0, s = cache->items; i < cache->cnt; i++, s++) {
		dur_len = max(dur_len, s->dur_len);
		res_len = max(res_len, s->err_len);
		sym_len = max(sym_len, s->sym_len);
		arg_len = max(arg_len, s->src_len);
	}
	/* the whole +2 and -2 business is due to the use of unicode characters */
	dur_len = max(dur_len, sizeof("DURATION") - 1);
	res_len = max(res_len, sizeof("RESULT") - 1);
	sym_len = max(sym_len, 2 + sizeof("FUNCTION CALL TRACE") - 1);
	arg_len = max(arg_len, sizeof("ARGS") - 1);
	/* but truncate to maximum buffer sizes */
	dur_len = min(dur_len, sizeof(s->dur));
	res_len = min(res_len, sizeof(s->err));
	sym_len = min(sym_len, sizeof(s->sym));
	arg_len = min(arg_len, sizeof(s->src));

	printf("%-*s   %-*s  %*s",
	       sym_len - 2, "FUNCTION CALL TRACE",
	       res_len, "RESULT",
	       dur_len, "DURATION");
	if (env.capture_args && env.args_fmt_mode == ARGS_FMT_COMPACT)
		printf("  %-*s", arg_len, "ARGS");
	printf("\n");

	printf("%-.*s   %-.*s  %.*s",
	       sym_len - 2, underline,
	       res_len, underline,
	       dur_len, underline);
	if (env.capture_args && env.args_fmt_mode == ARGS_FMT_COMPACT)
		printf("  %-.*s", arg_len, underline);
	printf("\n");

	/* emit line by line taking into account calculated lengths of each column */
	for (i = 0, s = cache->items; i < cache->cnt; i++, s++) {
		printf("%-*s   %-*s  %*s",
		       sym_len, s->sym,
		       res_len, s->err,
		       dur_len, s->dur);

		if (env.capture_args) {
			if (env.args_fmt_mode == ARGS_FMT_COMPACT)
				printf("  ");
			if (s->extra == FNARGS_MISSING_RECORD) {
				if (env.args_fmt_mode != ARGS_FMT_COMPACT)
					printf("\n\t");
				printf("... args data missing ...");
			} else if (s->extra) {
				struct func_args_item *fai = s->extra;

				emit_fn_args_data(ctx, stdout, s, fai->func_id, fai);
			}
		}

		printf("\n");
	}
}

static void prepare_stack_items(struct ctx *ctx, const struct fstack_item *fitem,
				const struct kstack_item *kitem)
{
	static struct a2l_resp resps[64];
	struct a2l_resp *resp = NULL;
	int symb_cnt = 0, i, line_off;
	const char *fname;
	struct stack_item *s;

	if (env.symb_mode != SYMB_NONE && ctx->a2l && kitem && !kitem->filtered) {
		long addr = kitem->addr;

		if (kitem->ksym && kitem->ksym && kitem->ksym->addr - kitem->addr == FTRACE_OFFSET)
			addr -= FTRACE_OFFSET;

		symb_cnt = addr2line__symbolize(ctx->a2l, addr, resps);
		if (symb_cnt < 0)
			symb_cnt = 0;
		if (symb_cnt > 0)
			resp = &resps[symb_cnt - 1];
	}

	s = get_stack_item(&stack_items1);
	if (!s) {
		fprintf(stderr, "Ran out of formatting space, some data will be omitted!\n");
		return;
	}

	/* kitem == NULL should be rare, either a bug or we couldn't get valid kernel stack trace */
	s->marks[0] = kitem ? ' ' : '!';
	s->marks[1] = (fitem && fitem->stitched) ? '*' : ' ';

	if (fitem && !fitem->finished) {
		snappendf(s->dur, "...");
		snappendf(s->err, "[...]");
	} else if (fitem) {
		snappendf(s->dur, "%ldus", fitem->lat / 1000);
		prepare_func_res(s, fitem->res, fitem->flags);
	}

	if (env.stack_emit_addrs) {
		if (kitem)
			snappendf(s->sym, "%c%016lx ", kitem->filtered ? '~' : ' ',  kitem->addr);
		else
			snappendf(s->sym, " %*s ", 16, "");
	}

	if (kitem && kitem->ksym)
		fname = kitem->ksym->name;
	else if (fitem)
		fname = fitem->name;
	else
		fname = "";
	snappendf(s->sym, "%s", fname);
	if (kitem && kitem->ksym) {
		snappendf(s->sym, env.stack_dec_offs ? "+%lu" : "+0x%lx",
			  kitem->addr - kitem->ksym->addr);
	}
	if (symb_cnt) {
		line_off = detect_linux_src_loc(resp->line);
		strip_out_column_num(resp->line + line_off);

		snappendf(s->src, "(");
		if (strcmp(fname, resp->fname) != 0)
			snappendf(s->src, "%s @ ", resp->fname);
		snappendf(s->src, "%s)", resp->line + line_off);
	}

	/* append inlined calls */
	for (i = 1, resp--; i < symb_cnt; i++, resp--) {
		s = get_stack_item(&stack_items1);
		if (!s) {
			fprintf(stderr, "Ran out of formatting space, some data will be omitted!\n");
			return;
		}

		line_off = detect_linux_src_loc(resp->line);
		strip_out_column_num(resp->line + line_off);

		snappendf(s->sym, "%*s. %s", env.stack_emit_addrs ? 18 : 0, "", resp->fname);
		snappendf(s->src, "(%s)", resp->line + line_off);
	}
}

static void print_stack_items(const struct stack_items_cache *cache)
{
	int dur_len = 5, err_len = 0, sym_len = 0, src_len = 0, i;
	const struct stack_item *s;

	/* calculate desired length of each auto-sized part of the output */
	for (i = 0, s = cache->items; i < cache->cnt; i++, s++) {
		dur_len = max(dur_len, s->dur_len);
		err_len = max(err_len, s->err_len);
		sym_len = max(sym_len, s->sym_len);
		src_len = max(src_len, s->src_len);
	}

	printf("\n");

	/* emit line by line taking into account calculated lengths of each column */
	for (i = 0, s = cache->items; i < cache->cnt; i++, s++) {
		printf("%c%c %*s %-*s  %-*s  %-*s\n",
		       s->marks[0], s->marks[1],
		       dur_len, s->dur, err_len, s->err,
		       sym_len, s->sym, src_len, s->src);
	}
}

static void prepare_lbr_items(struct ctx *ctx, long addr, struct stack_items_cache *cache)
{
	static struct a2l_resp resps[64];
	struct a2l_resp *resp = NULL;
	int symb_cnt = 0, line_off, i;
	const struct ksym *ksym;
	struct stack_item *s;

	s = get_stack_item(cache);
	if (!s) {
		fprintf(stderr, "Ran out of formatting space, some data will be omitted!\n");
		return;
	}

	if (env.stack_emit_addrs)
		snappendf(s->sym, "%016lx ", addr);

	ksym = ksyms__map_addr(ctx->ksyms, addr);
	if (ksym)
		snappendf(s->sym, env.stack_dec_offs ? "%s+%lu" : "%s+0x%lx",
			  ksym->name, addr - ksym->addr);

	if (!ctx->a2l || env.symb_mode == SYMB_NONE)
		return;

	symb_cnt = addr2line__symbolize(ctx->a2l, addr, resps);
	if (symb_cnt <= 0)
		return;

	resp = &resps[symb_cnt - 1];
	line_off = detect_linux_src_loc(resp->line);
	strip_out_column_num(resp->line + line_off);

	snappendf(s->src, "(");
	if (strcmp(ksym->name, resp->fname) != 0)
		snappendf(s->src, "%s @ ", resp->fname);
	snappendf(s->src, "%s)", resp->line + line_off);

	for (i = 1, resp--; i < symb_cnt; i++, resp--) {
		line_off = detect_linux_src_loc(resp->line);
		strip_out_column_num(resp->line + line_off);

		s = get_stack_item(cache);
		if (!s) {
			fprintf(stderr, "Ran out of formatting space, some data will be omitted!\n");
			return;
		}
		if (env.stack_emit_addrs)
			snappendf(s->sym, "%*s ", 16, "");
		snappendf(s->sym, ". %s", resp->fname);
		snappendf(s->src, "(%s)", resp->line + line_off);
	}
}

static void print_lbr_items(int lbr_from, int lbr_to,
			    const struct stack_items_cache *cache1, int rec_cnts1[MAX_LBR_ENTRIES],
			    const struct stack_items_cache *cache2, int rec_cnts2[MAX_LBR_ENTRIES])
{
	int sym_len1 = 0, sym_len2 = 0, src_len1 = 0, src_len2 = 0, i, j, k;
	const struct stack_item *s1, *s2;

	/* calculate desired length of each auto-sized part of the output */
	for (i = 0, s1 = cache1->items; i < cache1->cnt; i++, s1++) {
		sym_len1 = max(sym_len1, s1->sym_len);
		src_len1 = max(src_len1, s1->src_len);
	}
	for (j = 0, s2 = cache2->items; j < cache2->cnt; j++, s2++) {
		sym_len2 = max(sym_len2, s2->sym_len);
		src_len2 = max(src_len2, s2->src_len);
	}

	printf("\n");

	/* emit each LBR record (which can contain multiple lines) */
	for (i = 0, j = 0, k = lbr_from; k >= lbr_to; k--) {
		bool first = true;

		while (i < rec_cnts1[k] || j < rec_cnts2[k]) {
			s1 = i < rec_cnts1[k] ? &cache1->items[i++] : NULL;
			s2 = j < rec_cnts2[k] ? &cache2->items[j++] : NULL;

			if (first)
				printf("[#%02d] ", k);
			else
				printf("      ");
			printf("%-*s %-*s  %s  %-*s %-*s\n",
			       sym_len1, s1 ? s1->sym : "",
			       src_len1, s1 ? s1->src : "",
			       first ? "->" : "  ",
			       sym_len2, s2 ? s2->sym : "",
			       src_len2, s2 ? s2->src : "");

			first = false;
		}
	}
}


static bool lbr_matches(unsigned long addr, unsigned long start, unsigned long end)
{
	if (!start)
		return true;

	return start <= addr && addr < end;
}

static void output_lbrs(struct ctx *dctx, struct session *sess,
			unsigned long fn_start, unsigned long fn_end)
{
	int lbr_cnt, lbr_from, lbr_to = 0;
	int rec_cnts1[MAX_LBR_ENTRIES] = {};
	int rec_cnts2[MAX_LBR_ENTRIES] = {};
	bool found_useful_lbrs = false;
	int i;

	lbr_cnt = sess->lbrs_sz / sizeof(struct perf_branch_entry);
	lbr_from = lbr_cnt - 1;

	/* Filter out last few irrelevant LBRs that captured
	 * internal BPF/kprobe/perf jumps. For that, find the
	 * first LBR record that overlaps with the last traced
	 * function. All the records after that are assumed
	 * relevant.
	 */
	for (i = 0, lbr_to = 0; i < lbr_cnt; i++, lbr_to++) {
		if (lbr_matches(sess->lbrs[i].from, fn_start, fn_end) ||
		    lbr_matches(sess->lbrs[i].to, fn_start, fn_end)) {
			found_useful_lbrs = true;
			break;
		}
	}
	if (!found_useful_lbrs ||
	    env.stack_emit_all || (env.debug_feats & DEBUG_FULL_LBR))
		lbr_to = 0;

	if (env.lbr_max_cnt && lbr_from - lbr_to + 1 > env.lbr_max_cnt)
		lbr_from = min(lbr_cnt - 1, lbr_to + env.lbr_max_cnt - 1);

	stack_items1.cnt = 0;
	stack_items2.cnt = 0;
	for (i = lbr_from; i >= lbr_to; i--) {
		prepare_lbr_items(dctx, sess->lbrs[i].from, &stack_items1);
		prepare_lbr_items(dctx, sess->lbrs[i].to, &stack_items2);

		rec_cnts1[i] = stack_items1.cnt;
		rec_cnts2[i] = stack_items2.cnt;
	}

	print_lbr_items(lbr_from, lbr_to,
			&stack_items1, rec_cnts1,
			&stack_items2, rec_cnts2);

	if (!found_useful_lbrs)
		printf("[LBR] No relevant LBR data were captured, showing unfiltered LBR stack!\n");
}

static int output_call_stack(struct ctx *dctx,
			     const struct fstack_item *fstack, int fstack_n,
			     const struct kstack_item *kstack, int kstack_n)
{
	int i, j;

	/* Emit combined fstack/kstack + errors stack trace */
	stack_items1.cnt = 0;

	i = 0;
	j = 0;
	while (i < fstack_n) {
		const struct fstack_item *fitem = &fstack[i];
		const struct kstack_item *kitem = j < kstack_n ? &kstack[j] : NULL;

		if (!kitem) {
			/* this shouldn't happen unless we got no kernel stack
			 * or there is some bug
			 */
			prepare_stack_items(dctx, fitem, NULL);
			i++;
			continue;
		}

		/* exhaust unknown kernel stack items, assuming we should find
		 * kstack_item matching current fstack_item eventually, which
		 * should be the case when kernel stack trace is correct
		 */
		if (!kitem->ksym || kitem->filtered
		    || strcmp(kitem->ksym->name, fitem->name) != 0) {
			prepare_stack_items(dctx, NULL, kitem);
			j++;
			continue;
		}

		/* happy case, lots of info, yay */
		prepare_stack_items(dctx, fitem, kitem);
		i++;
		j++;
		continue;
	}

	for (; j < kstack_n; j++) {
		prepare_stack_items(dctx, NULL, &kstack[j]);
	}

	print_stack_items(&stack_items1);

	return 0;
}

static int handle_session_end(struct ctx *dctx, struct session *sess, const struct session_end *r)
{
	static struct fstack_item fstack[MAX_FSTACK_DEPTH];
	static struct kstack_item kstack[MAX_KSTACK_DEPTH];
	unsigned long fn_start = 0, fn_end = 0;
	int fstack_n, kstack_n, ret = 0;
	char ts1[64], ts2[64];
	const struct call_stack *s = &r->stack;

	if (r->ignored)
		goto out_purge;

	if (!s->is_err && !env.emit_success_stacks)
		goto out_purge;

	if (s->is_err && env.has_error_filter && !should_report_stack(dctx, s))
		goto out_purge;

	if (env.debug) {
		printf("GOT %s STACK (depth %u):\n", s->is_err ? "ERROR" : "SUCCESS", s->max_depth);
		printf("DEPTH %d MAX DEPTH %d SAVED DEPTH %d MAX SAVED DEPTH %d\n",
				s->depth, s->max_depth, s->saved_depth, s->saved_max_depth);
	}

	fstack_n = filter_fstack(dctx, fstack, s);
	if (fstack_n < 0) {
		fprintf(stderr, "FAILURE DURING FILTERING FUNCTION STACK!!! %d\n", fstack_n);
		ret = -EINVAL;
		goto out_purge;
	}
	kstack_n = filter_kstack(dctx, kstack, s);
	if (kstack_n < 0) {
		fprintf(stderr, "FAILURE DURING FILTERING KERNEL STACK!!! %d\n", kstack_n);
		ret = -EINVAL;
		goto out_purge;
	}
	if (env.debug) {
		printf("FSTACK (%d items):\n", fstack_n);
		printf("KSTACK (%d items out of original %ld):\n", kstack_n, s->kstack_sz / 8);
	}

	ts_to_str(ktime_to_ts(sess->start_ts), ts1, sizeof(ts1));
	ts_to_str(ktime_to_ts(r->emit_ts), ts2, sizeof(ts2));
	printf("%s -> %s TID/PID %d/%d (%s/%s):\n", ts1, ts2, sess->pid, sess->tgid,
	       sess->task_comm, sess->proc_comm);

	/* Emit more verbose outputs before more succinct and high signal output.
	 * Func trace goes first, then LBR, then (error) stack trace, each
	 * conditional on being enabled to be collected and output
	 */

	/* Emit detailed function calls trace, but only if we have completed
	 * call stack trace (depth == 0)
	 */
	if (env.emit_func_trace && s->depth == 0) {
		prepare_ft_items(dctx, &stack_items1, sess->pid, r->last_seq_id);
		print_ft_items(dctx, &stack_items1);
	}

	/* Determine address range of deepest nested function */
	if (fstack_n > 0) {
		const struct fstack_item *fitem = &fstack[fstack_n - 1];

		if (fitem->finfo->size) {
			fn_start = fitem->finfo->addr;
			fn_end = fitem->finfo->addr + fitem->finfo->size;
		}
	}

	/* LBR output */
	if (env.use_lbr) {
		if (r->lbrs_sz > 0 && !sess->lbrs)
			printf("LBR data was dropped and is missing in this sample!\n");
		else if (r->lbrs_sz < 0)
			printf("Failed to capture LBR entries: %d\n", r->lbrs_sz);
		else
			output_lbrs(dctx, sess, fn_start, fn_end);
	}

	/* Emit combined fstack/kstack + errors stack trace */
	output_call_stack(dctx, fstack, fstack_n, kstack, kstack_n);

	if (r->dropped_records) {
		printf("WARNING! Sample data incomplete! %d record%s dropped. Consider increasing --ringbuf-map-size.\n",
		       r->dropped_records, r->dropped_records == 1 ? "" : "s");
	}

	printf("\n\n");

out_purge:
	purge_session(dctx, r->pid);

	return ret;
}

int handle_event(void *ctx, void *data, size_t data_sz)
{
	enum rec_type type = *(enum rec_type *)data;
	static long prev_dropped_sessions;
	long cur_dropped_sessions = read_dropped_sessions();
	struct session *sess;

	if (cur_dropped_sessions != prev_dropped_sessions) {
		printf("WARNING! %ld samples were dropped, you are missing data! Consider increasing --ringbuf-map-size.\n",
		       cur_dropped_sessions - prev_dropped_sessions);
		prev_dropped_sessions = cur_dropped_sessions;
	}

	switch (type) {
	case REC_SESSION_START:
		return handle_session_start(ctx, data);
	case REC_FUNC_TRACE_ENTRY:
	case REC_FUNC_TRACE_EXIT: {
		const struct func_trace_entry *r = data;

		if (!hashmap__find(&sessions_hash, (long)r->pid, &sess)) {
			fprintf(stderr, "BUG: PID %d session data not found (%s)!\n", r->pid,
				r->type == REC_FUNC_TRACE_ENTRY ? "FUNC_TRACE_ENTRY" : "FUNC_TRACE_EXIT");
			return -EINVAL;
		}
		return handle_func_trace_entry(ctx, sess, r);
	}
	case REC_FUNC_ARGS_CAPTURE: {
		struct func_args_capture *r = data;

		if (!hashmap__find(&sessions_hash, (long)r->pid, &sess)) {
			fprintf(stderr, "BUG: PID %d session data not found (FUNC_ARGS_CAPTURE)!\n", r->pid);
			return -EINVAL;
		}
		return handle_func_args_capture(ctx, sess, r);
	}
	case REC_LBR_STACK: {
		const struct lbr_stack *r = data;

		if (!hashmap__find(&sessions_hash, (long)r->pid, &sess)) {
			fprintf(stderr, "BUG: PID %d session data not found (LBR_STACK)!\n", r->pid);
			return -EINVAL;
		}
		return handle_lbr_stack(ctx, sess, r);
	}
	case REC_SESSION_END: {
		const struct session_end *r = data;

		if (!hashmap__find(&sessions_hash, (long)r->pid, &sess)) {
			fprintf(stderr, "BUG: PID %d session data not found (SESSION_END)!\n", r->pid);
			return -EINVAL;
		}
		return handle_session_end(ctx, sess, r);
	}
	default:
		fprintf(stderr, "Unrecognized record type %d\n", type);
		return -ENOTSUP;
	}
}

__attribute__((constructor))
static void logic_init(void)
{
	 memset(underline, '-', sizeof(underline) - 1);
	 memset(spaces, ' ', sizeof(spaces) - 1);
}

__attribute__((destructor))
static void logic_cleanup(void)
{
	free_sessions();

	free(stack_items1.items);
	free(stack_items2.items);
}
