// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2024 Meta Platforms, Inc. */
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/btf.h>
#include <bpf/bpf.h>
#include <linux/ptrace.h>
#include "env.h"
#include "mass_attacher.h"
#include "utils.h"
#include "logic.h"
#include "hashmap.h"
#include "retsnoop.h"
#include "kmem_reader.skel.h"
#include "ksyms.h"

static struct func_args_info *fn_infos;
static int fn_info_cnt, fn_info_cap;

static struct ctx_args_info *ctx_infos;
static int ctx_info_cnt, ctx_info_cap;

const struct func_args_info *func_args_info(int func_id)
{
	return &fn_infos[func_id];
}

const struct ctx_args_info *ctx_args_info(int probe_id)
{
	return &ctx_infos[probe_id];
}

static bool btf_is_fixed_sized(const struct btf *btf, const struct btf_type *t)
{
	return btf_is_int(t) || btf_is_any_enum(t) || btf_is_composite(t);
}

static bool btf_is_char(const struct btf *btf, const struct btf_type *t)
{
	if (!btf_is_int(t))
		return false;
	if (btf_int_encoding(t) & BTF_INT_CHAR) /* one can hope, but compilers don't set this */
		return true;
	return strcmp(btf__name_by_offset(btf, t->name_off), "char") == 0;
}

static bool is_printf_like_func(const struct btf *btf, const struct btf_type *fn_t)
{
	const struct btf_param *p;
	const struct btf_type *t;
	int n = btf_vlen(fn_t);
	bool is_const = false;

	/* we need at least fmt + vararg params */
	if (n < 2)
		return false;

	/* last param should be VOID */
	p = btf_params(fn_t) + n - 1;
	if (p->type != 0)
		return false;

	/* last arg before `...` should be a `const char *` param */
	p = btf_params(fn_t) + n - 2;
	t = btf_strip_mods_and_typedefs(btf, p->type, NULL);
	if (!btf_is_ptr(t))
		return false;

	/* resolve pointer, and check if we have `const char` */
	t = btf__type_by_id(btf, t->type);
	while (btf_is_mod(t) || btf_is_typedef(t)) {
		if (btf_is_const(t))
			is_const = true;
		t = btf__type_by_id(btf, t->type);
	}
	return btf_is_char(btf, t) && is_const;
}

static int calc_printf_fmt_arg_cnt(const struct func_args_item *fai,
				   int fmt_arg_idx, const void *data)
{
	const char *fmt;
	int n = 0;

	if (!data || fai->arg_lens[fmt_arg_idx] <= 0)
		return -EINVAL;

	fmt = data;
	while (*fmt) {
		if (*fmt == '%' && *(fmt + 1) == '%') {
			fmt += 2;
			continue;
		}
		if (*fmt == '%')
			n++;
		fmt++;
	}
	return n;
}

#ifdef __x86_64__
static bool is_arg_in_reg(int arg_idx, const char **reg_name)
{
	switch (arg_idx) {
	case 0: return *reg_name = "rdi", true;
	case 1: return *reg_name = "rsi", true;
	case 2: return *reg_name = "rdx", true;
	case 3: return *reg_name = "rcx", true;
	case 4: return *reg_name = "r8", true;
	case 5: return *reg_name = "r9", true;
	default: return *reg_name = "<inval>", false;
	}
}
#elif defined(__aarch64__)
static bool is_arg_in_reg(int arg_idx, const char **reg_name)
{
	switch (arg_idx) {
	case 0: return *reg_name = "x0", true;
	case 1: return *reg_name = "x1", true;
	case 2: return *reg_name = "x2", true;
	case 3: return *reg_name = "x3", true;
	case 4: return *reg_name = "x4", true;
	case 5: return *reg_name = "x5", true;
	case 6: return *reg_name = "x6", true;
	case 7: return *reg_name = "x7", true;
	default: return *reg_name = "<inval>", false;
	}
}
#else
static bool is_arg_in_reg(int arg_idx, const char **reg_name)
{
	*reg_name = "<unsupported>";
	return false;
}
#endif

static int realign_stack_off(int stack_off)
{
#if defined(__x86_64__)
	/* x86-64 stack is 8-byte aligned */
	return (stack_off + 7) & ~7;
#elif defined(__aarch64__)
	/* ARM64 stack is 16-byte aligned */
	return (stack_off + 15) & ~15;
#else
	return stack_off;
#endif
}

/* Prepare specifications of function arguments capture (happening on BPF side)
 * and post-processing (happening on user space side)
 */
int prepare_fn_args_specs(int func_id, const struct mass_attacher_func_info *finfo)
{
	struct func_args_info *fn_args;
	struct func_arg_spec *spec;
	const struct btf_type *fn_t, *t;
	int i, n, reg_idx = 0;
#if defined(__x86_64__)
	int stack_off = 8; /* 8 bytes for return address */
#elif defined(__aarch64__)
	/* From the AArch64 ABI Function Call Standard: "The next stacked argument
	 * address (NSAA) is set to the current stack-pointer value (SP)."
	 */
	int stack_off = 0; 
						
#else
	int stack_off = 0;
#endif
	bool is_printf_like = false;

	if (func_id >= fn_info_cnt) {
		int new_cap = max((func_id + 1) * 4 / 3, 16);
		void *tmp;

		tmp = realloc(fn_infos, new_cap * sizeof(*fn_infos));
		if (!tmp)
			return -ENOMEM;
		fn_infos = tmp;

		memset(fn_infos + fn_info_cnt, 0, (new_cap - fn_info_cnt) * sizeof(*fn_infos));

		fn_info_cnt = func_id + 1;
		fn_info_cap = new_cap;
	}
	fn_args = &fn_infos[func_id];

	dlog("Function '%s%s%s%s' args spec:", NAME_MOD(finfo->name, finfo->module));

	if (!finfo->btf || finfo->btf_id == 0) {
		const char *reg_name;

		/* no BTF information, fallback to generic arch convention */
		fn_args->arg_spec_cnt = 6;
		for (i = 0; is_arg_in_reg(i, &reg_name); i++) {
			spec = &fn_args->arg_specs[i];

			spec->btf_id = 0;
			spec->arg_flags = 8; /* data length */
			spec->arg_flags |= FNARGS_REG << FNARGS_LOC_SHIFT;
			spec->arg_flags |= i << FNARGS_REGIDX_SHIFT;

			dlog(" arg#%d=%s", i, reg_name);
		}
		dlog(" (NO BTF INFO)\n");
		return 0;
	}

	fn_t = btf__type_by_id(finfo->btf, finfo->btf_id); /* FUNC */
	fn_t = btf__type_by_id(finfo->btf, fn_t->type); /* FUNC_PROTO */
	is_printf_like = is_printf_like_func(finfo->btf, fn_t);

	n = btf_vlen(fn_t);
	if (n > MAX_FNARGS_ARG_SPEC_CNT)
		n = MAX_FNARGS_ARG_SPEC_CNT;

	fn_args->arg_spec_cnt = (is_printf_like ? MAX_FNARGS_ARG_SPEC_CNT : n);

	for (i = 0; i < fn_args->arg_spec_cnt; i++) {
		int btf_id, data_len, true_len;
		const char *reg1_name, *reg2_name;
		bool is_vararg = is_printf_like && (i >= n - 1);

		spec = &fn_args->arg_specs[i];
		spec->pointee_btf_id = 0;
		spec->arg_flags = 0;

		if (is_vararg) {
			/* if function looks like printf-like, we have a special vararg logic */
			spec->name = "(vararg)";
			spec->btf_id = 0;
			spec->arg_flags |= FNARGS_KIND_VARARG << FNARGS_KIND_SHIFT;
		} else {
			const struct btf_param *p = btf_params(fn_t) + i;

			spec->name = btf__name_by_offset(finfo->btf, p->name_off);
			spec->btf_id = p->type;
		}

		if (spec->btf_id == 0 && !is_vararg) {
			/* non-printf vararg, we don't know what to do with this, skip */
			dlog(" (vararg)");
			spec->arg_flags = FNARGS_UNKN_VARARG;
			continue;
		}

		dlog(" %s=(", spec->name);

		t = btf_strip_mods_and_typedefs(finfo->btf, spec->btf_id, &btf_id);
		if (is_vararg || btf_is_fixed_sized(finfo->btf, t) || btf_is_ptr(t)) {
			true_len = (is_vararg || btf_is_ptr(t)) ? 8 : t->size;
			data_len = min(true_len, env.args_max_sized_arg_size);

			if (true_len <= 8 && is_arg_in_reg(reg_idx, &reg1_name)) {
				/* fits in one register */
				spec->arg_flags |= data_len;
				spec->arg_flags |= FNARGS_REG << FNARGS_LOC_SHIFT;
				spec->arg_flags |= reg_idx << FNARGS_REGIDX_SHIFT;
				dlog("%s", reg1_name);
				reg_idx += 1;
			} else if (true_len <= 16 &&
				   is_arg_in_reg(reg_idx, &reg1_name) &&
				   is_arg_in_reg(reg_idx + 1, &reg2_name)) {
				/* passed in a pair of registers */
				spec->arg_flags |= data_len;
				spec->arg_flags |= FNARGS_REG_PAIR << FNARGS_LOC_SHIFT;
				spec->arg_flags |= reg_idx << FNARGS_REGIDX_SHIFT;
				reg_idx += 2;
				dlog("%s:%s", reg1_name, reg2_name);
			} else {
				/* passed on the stack */
				if (stack_off > FNARGS_STACKOFF_MAX) {
					dlog("fp+%d(TOO LARGE!!!)", stack_off);
					stack_off = realign_stack_off(stack_off + true_len);
					spec->arg_flags = FNARGS_STACKOFF_2BIG;
					goto skip_arg;
				} else {
					spec->arg_flags |= data_len;
					spec->arg_flags |= FNARGS_STACK << FNARGS_LOC_SHIFT;
					/* stack offset is recorded in 8 byte increments */
					spec->arg_flags |= (stack_off / 8) << FNARGS_STACKOFF_SHIFT;
					dlog("fp+%d", stack_off);
					stack_off = realign_stack_off(stack_off + true_len);
				}
			}
			spec->arg_flags |= FNARGS_KIND_RAW << FNARGS_KIND_SHIFT;
		} else {
			/* unrecognized, read raw 8 byte value, assume single register */
			true_len = data_len = -1;
			dlog("!!!UNKNOWN ARG #%d KIND %d!!!", i, btf_kind(t));
			spec->arg_flags = FNARGS_UNKN; /* skip it */
		}

		if (btf_is_ptr(t)) {
			dlog("->");

			/* clear out length, it means pointee size for pointer arguments */
			spec->arg_flags &= ~FNARGS_LEN_MASK;

			/* NOTE: we fill out spec->pointee_btf_id here */
			t = btf_strip_mods_and_typedefs(finfo->btf, t->type, &spec->pointee_btf_id);
			if (btf_is_char(finfo->btf, t)) {
				/* varlen string */
				true_len = -1; /* mark that it's variable-length, for logging */
				data_len = env.args_max_str_arg_size;
				spec->arg_flags |= data_len;
				spec->arg_flags |= FNARGS_KIND_STR << FNARGS_KIND_SHIFT;
				spec->pointee_btf_id = -1; /* special string marker */
				dlog("str");
			} else if (btf_is_fixed_sized(finfo->btf, t)) {
				true_len = t->size;
				data_len = min(true_len, env.args_max_sized_arg_size);
				spec->arg_flags |= data_len;
				spec->arg_flags |= FNARGS_KIND_PTR << FNARGS_KIND_SHIFT;
				dlog("ptr_id=%d", spec->pointee_btf_id);
			} else {
				/* generic pointer, treat as u64 */
				true_len = data_len = 8; /* sizeof(void *), assume 64-bit */
				spec->arg_flags |= data_len; /* NOTE: no FNARGS_PTR flags */
				spec->arg_flags |= FNARGS_KIND_RAW << FNARGS_KIND_SHIFT;
				spec->pointee_btf_id = 0; /* raw pointer doesn't set pointee */
				dlog("raw");
			}
		}

skip_arg:
		if (data_len < 0) /* unknown */
			dlog(",len=??");
		else if (is_vararg) { /* printf-like vararg */
			/* nothing, it's implicitly 8 bytes */
		} else if (true_len < 0) /* variable-sized */
			dlog(",len=str(%d)", data_len);
		else if (true_len != data_len) /* truncated */
			dlog(",len=%d(%d)", true_len, data_len);
		else /* full data */
			dlog(",len=%d", data_len);

		if (is_vararg)
			dlog(")");
		else
			dlog(",btf_id=%d)", spec->btf_id);
	}

	dlog("\n");

	fn_args->btf = finfo->btf;;

	return 0;
}

int handle_fnargs_capture(struct ctx *ctx, struct session *sess,
			  const struct rec_fnargs_capture *r)
{
	struct func_args_item *fai;
	void *tmp;

	tmp = realloc(sess->fn_args_entries, (sess->fn_args_cnt + 1) * sizeof(sess->fn_args_entries[0]));
	if (!tmp)
		return -ENOMEM;
	sess->fn_args_entries = tmp;

	fai = &sess->fn_args_entries[sess->fn_args_cnt];
	fai->func_id = r->func_id;
	fai->seq_id = r->seq_id;
	fai->data_len = r->data_len;
	fai->arg_ptrs = r->arg_ptrs;
	fai->arg_data = malloc(fai->data_len);
	memcpy(fai->arg_lens, r->arg_lens, sizeof(r->arg_lens));
	if (!fai->arg_data)
		return -ENOMEM;
	memcpy(fai->arg_data, r->arg_data, r->data_len);

	sess->fn_args_cnt++;

	return 0;
}

static void sanitize_string(char *s, size_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (!isprint(s[i]))
			s[i] = ' ';
	}
	s[len - 1] = '\0';
}

static void btf_data_dump_printf(void *ctx, const char *fmt, va_list args)
{
	struct fmt_buf *b = ctx;

	vbnappendf(b, fmt, args);
}

static void fmt_capture_item(struct fmt_buf *b, const struct btf *btf,
			     int btf_id, int pointee_btf_id,
			     void *data, size_t data_len, int indent_shift)
{
	struct btf_data_dump_opts opts = {};
	int err;

	if (!btf) {
		char buf[32];

		/* fallback "raw registers" mode, data_len should be 8 */
		snprintf_smart_uint(buf, sizeof(buf), *(long long *)data);
		bnappendf(b, "%s", buf);

		return;
	}

	if (pointee_btf_id < 0) {
		/* variable-length string */
		sanitize_string(data, data_len);
		bnappendf(b, "'%s'", (char *)data);
		return;
	}

	if (pointee_btf_id) /* append pointer mark */
		bnappendf(b, "&");

	opts.emit_zeroes = false;
	opts.indent_str = "    ";
	opts.indent_level = 0;
	opts.indent_shift = indent_shift;
	opts.skip_names = false;
	if (env.args_fmt_mode == ARGS_FMT_VERBOSE) {
		opts.compact = false;
	} else {
		opts.compact = true;
	}

	err = btf_data_dump(btf, pointee_btf_id ?: btf_id, data, data_len,
			    btf_data_dump_printf, b, &opts);
	if (err == -E2BIG) {
		/* truncated data */
		bnappendf(b, UNICODE_HELLIP);
	} else if (err < 0) {
		/* unexpected error */
		const char *errstr = err_to_str(err);

		if (errstr)
			bnappendf(b, "...DUMP ERR=-%s...", errstr);
		else
			bnappendf(b, "...DUMP ERR=%d...", err);
	}
}

void emit_fnargs_data(FILE *f, struct stack_item *s,
		      const struct func_args_info *fn_args,
		      const struct func_args_item *fai,
		      int indent_shift)
{
	int i, len, vararg_start_idx = 0, kind, vararg_end_idx = 0;
	void *data = fai->arg_data, *prev_data = NULL;
	const char *sep = env.args_fmt_mode == ARGS_FMT_COMPACT ? "" : " ";
	char buf[32];

	for (i = 0; i < fn_args->arg_spec_cnt; i++) {
		const struct func_arg_spec *spec = &fn_args->arg_specs[i];
		int width_lim = env.args_fmt_max_arg_width, vararg_n;
		struct fmt_buf b;
		bool is_vararg, has_ptr;

		has_ptr = fai->arg_ptrs & (1 << i);

		kind = (spec->arg_flags & FNARGS_KIND_MASK) >> FNARGS_KIND_SHIFT;
		is_vararg = (kind == FNARGS_KIND_VARARG);
		if (is_vararg && vararg_start_idx == 0) {
			vararg_start_idx = i;
			vararg_n = calc_printf_fmt_arg_cnt(fai, i - 1, prev_data);
			if (vararg_n < 0)
				vararg_end_idx = fn_args->arg_spec_cnt - 1;
			else
				vararg_end_idx = i + vararg_n - 1;
		}
		if (is_vararg && i > vararg_end_idx)
			break;

		/* verbose args output mode doesn't have width limit */
		if (env.args_fmt_mode == ARGS_FMT_VERBOSE)
			width_lim = 0;
		b = FMT_FILE(f, s->src, width_lim);

		if (env.args_fmt_mode == ARGS_FMT_COMPACT)
			fprintf(f, "%s", i == 0 ? "" : " ");
		else /* emit Unicode's slightly smaller-sized '>' as a marker of an argument */
			fprintf(f, "\n%*.s%s ", indent_shift, "", UNICODE_RANGLEQUOT);
		if (fn_args->btf) {
			if (is_vararg)
				fprintf(f, "vararg%d%s=%s", i - vararg_start_idx, sep, sep);
			else
				fprintf(f, "%s%s=%s", spec->name, sep, sep);
		} else { /* "raw" BTF-less mode */
			fprintf(f, "arg%d%s=%s", i, sep, sep);
		}

		len = fai->arg_lens[i];

		/* for successfully captured vararg we will have arg_ptrs bit set */
		if (is_vararg && (len >= 0 || has_ptr)) {
			if (!has_ptr) { /* not a kernel pointer */
				snprintf_smart_uint(buf, sizeof(buf), *(long long *)data);
				bnappendf(&b, "%s", buf);
				prev_data = data;
				data += 8;
			} else if (len <= 0) { /* looked like pointer, but no string data */
				snprintf_smart_uint(buf, sizeof(buf), *(long long *)data);
				bnappendf(&b, "%s", buf);
				prev_data = data;
				data += 8;
			} else { /* we captured some string data, print both raw value and string */
				if (env.args_capture_raw_ptrs)
					bnappendf(&b, "(0x%llx)", *(long long *)data);
				data += 8;
				sanitize_string(data, len);
				bnappendf(&b, "'%s'", (char *)data);
				prev_data = data;
				data += (len + 7) / 8 * 8;
			}
			goto print_ellipsis;
		}

		if (env.args_capture_raw_ptrs && has_ptr) {
			bnappendf(&b, "(0x%llx)", *(long long *)data);
			data += 8;
		}
		prev_data = data;

		if (len == 0) {
			/* we encode special conditions in REGIDX mask */
			switch (spec->arg_flags & FNARGS_REGIDX_MASK) {
			case FNARGS_UNKN_VARARG:
				bnappendf(&b, "(vararg)");
				break;
			case FNARGS_UNKN:
				bnappendf(&b, "(unsupp)");
				break;
			case FNARGS_STACKOFF_2BIG:
				bnappendf(&b, "(stack-too-far)");
				break;
			default:
				bnappendf(&b, "(skipped)");
			}
		} else if (len == -ENODATA) {
			bnappendf(&b, "NULL");
		} else if (len == -ENOSPC) {
			bnappendf(&b, "(trunc)");
		} else if (len < 0) {
			const char *errstr = err_to_str(len);

			if (errstr)
				bnappendf(&b, "<ERR:-%s>", errstr);
			else
				bnappendf(&b, "<ERR:%d>", len);
		} else {
			fmt_capture_item(&b, fn_args->btf, spec->btf_id, spec->pointee_btf_id,
				         data, len, indent_shift);
			data += (len + 7) / 8 * 8;
		}

print_ellipsis:
		/* append Unicode horizontal ellipsis (single-character triple dots)
		 * if output was truncated to mark its truncation visually
		 */
		if (width_lim && b.sublen > b.max_sublen)
			fprintf(f, "%s", UNICODE_HELLIP);
	}
}

void emit_ctxargs_data(FILE *f, struct stack_item *s, int indent_shift,
		       const struct inj_probe_info *inj,
		       const struct ctx_capture_item *cci)
{
	const char *sep = env.args_fmt_mode == ARGS_FMT_COMPACT ? "" : " ";
	const struct ctx_args_info *info = ctx_args_info(cci->probe_id);
	void *data = cci->data;
	int i, len;

	for (i = 0; i < info->spec_cnt; i++) {
		const struct ctx_arg_spec *spec = &info->specs[i];
		int width_lim = env.args_fmt_max_arg_width;
		struct fmt_buf b;
		bool has_ptr;

		has_ptr = cci->ptrs_mask & (1 << i);

		/* verbose args output mode doesn't have width limit */
		if (env.args_fmt_mode == ARGS_FMT_VERBOSE)
			width_lim = 0;
		b = FMT_FILE(f, s->src, width_lim);

		if (env.args_fmt_mode == ARGS_FMT_COMPACT)
			fprintf(f, "%s", i == 0 ? "" : " ");
		else /* emit Unicode's slightly smaller-sized '>' as a marker of an argument */
			fprintf(f, "\n%*.s%s ", indent_shift, "", UNICODE_RANGLEQUOT);

		if (info->btf) {
			fprintf(f, "%s%s=%s", spec->name, sep, sep);
		} else { /* "raw" BTF-less mode */
			fprintf(f, "ctx%d%s=%s", i, sep, sep);
		}

		len = cci->lens[i];

		if (env.args_capture_raw_ptrs && has_ptr) {
			bnappendf(&b, "(0x%llx)", *(long long *)data);
			data += 8;
		}

		if (len == 0) {
			bnappendf(&b, "(empty)");
		} else if (len == -ENODATA) {
			bnappendf(&b, "NULL");
		} else if (len == -ENOSPC) {
			bnappendf(&b, "(trunc)");
		} else if (len < 0) {
			const char *errstr = err_to_str(len);

			if (errstr)
				bnappendf(&b, "<ERR:-%s>", errstr);
			else
				bnappendf(&b, "<ERR:%d>", len);
		} else {
			fmt_capture_item(&b, info->btf, spec->btf_id, spec->pointee_btf_id,
					data, len, indent_shift);
			data += (len + 7) / 8 * 8;
		}

		/* append Unicode horizontal ellipsis (single-character triple dots)
		 * if output was truncated to mark its truncation visually
		 */
		if (width_lim && b.sublen > b.max_sublen)
			fprintf(f, "%s", UNICODE_HELLIP);
	}
}

int handle_ctx_capture(struct ctx *ctx, struct session *sess, const struct rec_ctxargs_capture *r)
{
	struct ctx_capture_item *d;
	void *tmp;

	tmp = realloc(sess->ctx_entries, (sess->ctx_cnt + 1) * sizeof(sess->ctx_entries[0]));
	if (!tmp)
		return -ENOMEM;
	sess->ctx_entries = tmp;

	d = &sess->ctx_entries[sess->ctx_cnt];
	d->probe_id = r->probe_id;
	d->seq_id = r->seq_id;
	d->data_len = r->data_len;
	d->ptrs_mask = r->ptrs_mask;
	memcpy(d->lens, r->lens, sizeof(r->lens));
	d->data = malloc(r->data_len);
	if (!d->data)
		return -ENOMEM;
	memcpy(d->data, r->data, r->data_len);

	sess->ctx_cnt++;

	return 0;
}

/* Prepare specifications of context arguments capture (happening on BPF side)
 * and post-processing (happening on user space side) for injected probes.
 */

static int pt_regs_btf_id;

static int prepare_kprobe_ctx_specs(int probe_id,
				    const struct inj_probe_info *inj,
				    struct ctx_args_info *info)
{
	struct ctx_arg_spec *spec;
	const struct btf_type *t;

	if (pt_regs_btf_id == 0)
		pt_regs_btf_id = btf__find_by_name_kind(info->btf, "pt_regs", BTF_KIND_STRUCT);

	if (pt_regs_btf_id < 0) {
		elog("Failed to find 'struct pt_regs' BTF type for injection probe: %d\n",
		     pt_regs_btf_id);
		return -ESRCH;
	}

	info->spec_cnt = 1;

	/* regs -> struct pt_regs */
	spec = &info->specs[0];
	spec->name = "regs";
	spec->btf_id = pt_regs_btf_id;

	t = btf__type_by_id(info->btf, pt_regs_btf_id);
	spec->flags = t->size;
	spec->flags |= CTXARG_KIND_VALUE << CTXARG_OFF_SHIFT;
	spec->flags |= 0 << CTXARG_OFF_SHIFT;

	return 0;
}

/* expects TYPEDEF -> PTR -> FUNC_PROTO, returns ID of FUNC_PROTO */
static bool btf_is_typedef_ptr_fnproto(const struct btf *btf, int btf_id, int *fn_btf_id)
{
	const struct btf_type *t;

	t = btf__type_by_id(btf, btf_id);
	if (!btf_is_typedef(t))
		return false;

	t = btf_strip_mods_and_typedefs(btf, t->type, NULL);
	if (!btf_is_ptr(t))
		return false;

	t = btf_strip_mods_and_typedefs(btf, t->type, fn_btf_id);
	if (!btf_is_func_proto(t))
		return false;

	return true;
}

/* expects FUNC -> FUNC_PROTO, returns IF of FUNC_PROTO */
static bool btf_is_func_fnproto(const struct btf *btf, int btf_id, int *fn_btf_id)
{
	const struct btf_type *t;

	t = btf__type_by_id(btf, btf_id);
	if (!btf_is_func(t))
		return false;

	t = btf_strip_mods_and_typedefs(btf, t->type, fn_btf_id);
	if (!btf_is_func_proto(t))
		return false;

	return true;
}

static int prepare_rawtp_ctx_specs(int probe_id,
				   const struct inj_probe_info *inj,
				   struct ctx_args_info *info)
{
	const struct btf *btf = info->btf;
	const struct btf_type *t, *tr, *ti;
	const struct btf_param *trp, *tip;
	char buf[256];
	int btf_id, traceiter_btf_id, i;

	/* Each raw tracepoint has a corresponding 'btf_trace_<name>' BTF type
	 * of the form TYPEDEF -> PTR -> FUNC_PROTO. The very first argument
	 * is always void * and isn't really a part of raw tracepoint data.
	 *
	 * E.g., for module_get raw tracepoint:
	 *
	 * typedef void (*btf_trace_module_get)(void *, struct module *, unsigned long);
	 *
	 * Unfortunately, parameter names are lost and can't be recovered from
	 * this type. BUT!
	 *
	 * Kernel also defines __traceiter_<name> FUNC -> FUNC_PROTO (and
	 * earlier it was called __tracepoint_iter_<name>, so we try to find
	 * that as well), which does preserve argument names.
	 *
	 * __traceiter_<name> doesn't record correct types, though, so we need
	 * to rely on both types for most complete information.
	 *
	 * Names are considered optional, so we don't fail if we don't find
	 * __traceiter/__tracepoint_iter types. But we do rely on btf_trace
	 * type heavily, so if it's not found, we bail.
	 */
	snprintf(buf, sizeof(buf), "btf_trace_%s", inj->rawtp.name);
	btf_id = btf__find_by_name_kind(btf, buf, BTF_KIND_TYPEDEF);
	if (btf_id < 0) {
		elog("Failed to find BTF type '%s' for raw tracepoint '%s': %d\n",
		     buf, inj->rawtp.name, btf_id);
		return -ESRCH;
	}
	if (!btf_is_typedef_ptr_fnproto(btf, btf_id, &btf_id)) {
		elog("Invalid form of BTF type '%s' for raw tracepoint '%s': %d\n",
		     buf, inj->rawtp.name, btf_id);
		return -ESRCH;
	}
	tr = btf__type_by_id(btf, btf_id);

	/* optionally find traceiter to recover argument names */
	snprintf(buf, sizeof(buf), "__traceiter_%s", inj->rawtp.name);
	traceiter_btf_id = btf__find_by_name_kind(btf, buf, BTF_KIND_FUNC);
	if (traceiter_btf_id < 0) {
		snprintf(buf, sizeof(buf), "__tracepoint_iter_%s", inj->rawtp.name);
		traceiter_btf_id = btf__find_by_name_kind(btf, buf, BTF_KIND_FUNC);
	}
	ti = traceiter_btf_id > 0 ? btf__type_by_id(btf, traceiter_btf_id) : NULL;
	if (ti && !btf_is_func_fnproto(btf, traceiter_btf_id, &traceiter_btf_id))
		ti = NULL;
	ti = traceiter_btf_id > 0 ? btf__type_by_id(btf, traceiter_btf_id) : NULL;

	/* we skip first `void *` param */
	info->spec_cnt = 0;
	for (i = 1; i < btf_vlen(tr) && info->spec_cnt < MAX_CTXARGS_SPEC_CNT; i++) {
		struct ctx_arg_spec *spec = &info->specs[info->spec_cnt];

		trp = btf_params(tr) + i;
		tip = ti ? btf_params(ti) + i : NULL;

		spec->btf_id = trp->type;
		spec->name = tip ? btf__str_by_offset(btf, tip->name_off) : "arg";
		spec->flags = (info->spec_cnt * 8) << CTXARG_OFF_SHIFT;

		t = btf_strip_mods_and_typedefs(btf, trp->type, NULL);
		if (btf_is_ptr(t)) {
			/* NOTE: we fill out spec->pointee_btf_id here */
			t = btf_strip_mods_and_typedefs(btf, t->type, &spec->pointee_btf_id);
			if (btf_is_char(btf, t)) {
				spec->flags |= env.args_max_str_arg_size;
				spec->flags |= CTXARG_KIND_PTR_STR << CTXARG_KIND_SHIFT;
				spec->pointee_btf_id = -1; /* special string marker */
			} else if (btf_is_fixed_sized(btf, t)) {
				spec->flags |= min(t->size, env.args_max_sized_arg_size);
				spec->flags |= CTXARG_KIND_PTR_FIXED << CTXARG_KIND_SHIFT;
			} else {
				/* generic pointer, treat as u64 */
				spec->flags |= 8;
				spec->flags |= CTXARG_KIND_VALUE << CTXARG_KIND_SHIFT;
				spec->pointee_btf_id = 0; /* raw pointer doesn't set pointee */
			}
		} else if (btf_is_fixed_sized(btf, t)) {
			spec->flags |= min(t->size, env.args_max_sized_arg_size);
			spec->flags |= CTXARG_KIND_VALUE << CTXARG_KIND_SHIFT;
		} else {
			dlog("!!!UNKNOWN ARG #%d KIND %d!!!", info->spec_cnt, btf_kind(t));
			spec->flags |= CTXARG_KIND_VALUE << CTXARG_OFF_SHIFT; /* no len, skip it */
		}

		info->spec_cnt++;
	}

	return 0;
}

static struct kmem_reader_bpf *kmem_skel;

static int prepare_tp_ctx_specs(int probe_id,
				const struct inj_probe_info *inj,
				struct ctx_args_info *info)
{
	const struct btf *btf = info->btf;
	const char trace_fn_pfx[] = "__bpf_trace_", data_loc_pfx[] = "__data_loc_";
	const char *tp_name = inj->tp.name, *tp_class;
	const struct btf_type *tp_t;
	char buf[256];
	int err, buf_sz = sizeof(buf), tp_btf_id, i;
	struct ksyms *ksyms = env.ctx.ksyms;
	const struct ksym *tp_map_sym, *trace_fn_sym;

	/*
	 * There are two (classic) tracepoint kinds:
	 *   - either defined with TRACE_EVENT() macro;
	 *   - or defined with DECLARE_EVENT_CLASS() + DEFINE_EVENT().
	 *
	 * TRACE_EVENT() is a simple case in which tracepoint name and
	 * tracepoint *class* is the same, and there is always
	 * `struct trace_event_raw_<name>` which describes memory layout of
	 * tracepoint's collection of assigned parameters (as opposed to raw
	 * tracepoint that just passes through original passed in arguments).
	 *
	 * The DEFINE_EVENT() case is much less convenient, because tracepoint
	 * *name* is different from tracepoint *class*, and kernel only
	 * defines `struct trace_event_raw_<class>` types. Also, there is no
	 * easy way to figure out name -> class mapping *from BTF type info*.
	 * So we need to do a bit more work to resolve tracepoint event to
	 * its class.
	 *
	 * Not everything is lost, though. Note that within the BPF
	 * subsystem's tracepoint plumbing we have this defined for each
	 * tracepoint (see include/trace/bpf_probe.h):
	 *
	 * static union {
	 * 	struct bpf_raw_event_map event;
	 * 	btf_trace_##call handler;
	 * } __bpf_trace_tp_map_##call __used __section("__bpf_raw_tp_map") = {
	 * 	.event = {
	 * 		.tp             = &__tracepoint_##call,
	 * 		.bpf_func       = __bpf_trace_##template,
	 * 		.num_args       = COUNT_ARGS(args),
	 * 		.writable_size  = size,
	 * 	},
	 * };
	 *
	 * In the above, `call` is *tracepoint name*, while `template` is
	 * *tracepoint class*. Above means that there is always
	 * __bpf_trace_tp_map_<name> variable (and a corresponding kallsyms
	 * symbol), effectively of type `struct bpf_raw_event_map` (we ignore
	 * the union which is there just for btf_trace_##call type preservation),
	 * which's .bpf_func field is set to an address of __bpf_trace_<class>
	 * function.
	 *
	 * So the game plan here is:
	 *   - find __bpf_trace_tp_map variable address from kallsyms;
	 *   - fetch the address of its .bpf_func field using trivial BPF
	 *     program that can read arbitrary kernel memory (kmem_reader.bpf.c);
	 *   - map that address to __bpf_trace function name (again through kallsyms);
	 *   - now we have *name* to *class* mapping, which now allows to find
	 *     correct trace_event_raw type.
	 *
	 * Easy peasy lemon squeezy!
	 */
	if (!kmem_skel) {
		kmem_skel = kmem_reader_bpf__open_and_load();
		if (!kmem_skel) {
			err = -errno;
			elog("Failed to load kmem_reader helper skeleton: %d\n", err);
			return err;
		}
	}

	snprintf(buf, buf_sz, "__bpf_trace_tp_map_%s", tp_name);
	tp_map_sym = ksyms__get_symbol(ksyms, buf, NULL, KSYM_DATA);
	if (!tp_map_sym) {
		elog("Failed to find '%s' kernel symbol for tracepoint '%s:%s'!\n",
		     buf, inj->tp.category, inj->tp.name);
		return -ESRCH;
	}

	/* We hard-code offsetof(struct bpf_raw_event_map, bpf_func), why would it change?
	 * We can always use BTF for this, if it ever causes any problem.
	 */
	kmem_skel->bss->addr = tp_map_sym->addr + 8;
	err = bpf_prog_test_run_opts(bpf_program__fd(kmem_skel->progs.kmem_read), NULL);
	if (err || kmem_skel->bss->read_err) {
		err = err ?: kmem_skel->bss->read_err;
		elog("Failed to read `%s.bpf_func` value at 0x%lx: %d\n",
		     buf, kmem_skel->bss->addr, err);
		return err;
	}

	trace_fn_sym = ksyms__map_addr(ksyms, kmem_skel->bss->value, KSYM_FUNC);
	if (!trace_fn_sym) {
		elog("Failed to resolve 0x%lx to `__bpf_trace_<class>` symbol for tracepoint '%s:%s'!\n",
		     kmem_skel->bss->value, inj->tp.category, inj->tp.name);
		return -ESRCH;
	}

	if (strncmp(trace_fn_sym->name, trace_fn_pfx, sizeof(trace_fn_pfx) - 1) != 0) {
		elog("Unexpected symbol '%s' (expected '%sxxx') found for tracepoint '%s:%s'!\n",
		     trace_fn_sym->name, trace_fn_pfx, inj->tp.category, inj->tp.name);
		return -ESRCH;
	}

	tp_class = trace_fn_sym->name + sizeof(trace_fn_pfx) - 1;
	snprintf(buf, buf_sz, "trace_event_raw_%s", tp_class);
	tp_btf_id = btf__find_by_name_kind(btf, buf, BTF_KIND_STRUCT);
	if (tp_btf_id < 0) {
		elog("Failed to find 'struct %s' for tracepoint '%s:%s'!\n",
		     buf, inj->tp.category, inj->tp.name);
		return tp_btf_id;
	}
	tp_t = btf__type_by_id(btf, tp_btf_id);

	/* we skip the first field (`struct trace_entry ent;`) */
	info->spec_cnt = 0;
	for (i = 1; i < btf_vlen(tp_t) && info->spec_cnt < MAX_CTXARGS_SPEC_CNT; i++) {
		struct ctx_arg_spec *spec = &info->specs[info->spec_cnt];
		const struct btf_member *m;
		const char *fname;
		const struct btf_type *t;
		int off, f_btf_id;

		m = btf_members(tp_t) + i;
		fname = btf__name_by_offset(btf, m->name_off);

		if (strcmp(fname, "__data") == 0)
			break;

		/* We don't support bitfields in tracepoint struct */
		if (btf_member_bitfield_size(tp_t, i)) {
			dlog("Skipping bitfield '%s' for tracepoint '%s:%s'...\n",
			     fname, inj->tp.category, inj->tp.name);
			continue;
		}

		spec->btf_id = m->type;

		off = btf_member_bit_offset(tp_t, i) / 8;
		spec->flags = off << CTXARG_OFF_SHIFT;

		t = btf_strip_mods_and_typedefs(btf, m->type, &f_btf_id);
		if (strncmp(fname, data_loc_pfx, sizeof(data_loc_pfx) - 1) == 0) {
			/* special varlen (usually string) "pointer" field */
			fname = fname + sizeof(data_loc_pfx) - 1;
			spec->flags |= env.args_max_str_arg_size;
			spec->flags |= CTXARG_KIND_TP_VARLEN << CTXARG_KIND_SHIFT;
			spec->pointee_btf_id = -1; /* special string marker */
		} else if (btf_is_ptr(t)) {
			/* NOTE: we fill out spec->pointee_btf_id here */
			t = btf_strip_mods_and_typedefs(btf, t->type, &spec->pointee_btf_id);
			if (btf_is_char(btf, t)) {
				spec->flags |= env.args_max_str_arg_size;
				spec->flags |= CTXARG_KIND_PTR_STR << CTXARG_KIND_SHIFT;
				spec->pointee_btf_id = -1; /* special string marker */
			} else if (btf_is_fixed_sized(btf, t)) {
				spec->flags |= min(t->size, env.args_max_sized_arg_size);
				spec->flags |= CTXARG_KIND_PTR_FIXED << CTXARG_KIND_SHIFT;
			} else {
				/* generic pointer, treat as u64 */
				spec->flags |= 8;
				spec->flags |= CTXARG_KIND_VALUE << CTXARG_KIND_SHIFT;
				spec->pointee_btf_id = 0; /* raw pointer doesn't set pointee */
			}
		} else if (btf_is_fixed_sized(btf, t) || btf_is_array(t)) {
			spec->flags |= min(btf__resolve_size(btf, f_btf_id),
					   env.args_max_sized_arg_size);
			spec->flags |= CTXARG_KIND_VALUE << CTXARG_KIND_SHIFT;
		} else {
			dlog("Skipping unknown field '%s' of BTF kind %d for tracepoint '%s:%s'...\n",
			     fname, btf_kind(t), inj->tp.category, inj->tp.name);
			continue;
		}

		spec->name = fname;

		info->spec_cnt++;
	}

	return 0;
}

int prepare_ctx_args_specs(int probe_id, const struct inj_probe_info *inj)
{
	struct ctx_args_info *ctx_args;
	char desc[256];
	int i, err = -EINVAL;

	snprintf_inj_probe(desc, sizeof(desc), inj);

	if (probe_id >= ctx_info_cnt) {
		int new_cap = max((probe_id + 1) * 4 / 3, 16);
		void *tmp;

		tmp = realloc(ctx_infos, new_cap * sizeof(*ctx_infos));
		if (!tmp)
			return -ENOMEM;
		ctx_infos = tmp;

		memset(ctx_infos + ctx_info_cnt, 0, (new_cap - ctx_info_cnt) * sizeof(*ctx_infos));

		ctx_info_cnt = probe_id + 1;
		ctx_info_cap = new_cap;
	}

	ctx_args = &ctx_infos[probe_id];
	ctx_args->btf = inj->btf;

	switch (inj->type) {
	case INJ_KPROBE:
	case INJ_KRETPROBE:
		err = prepare_kprobe_ctx_specs(probe_id, inj, ctx_args);
		break;
	case INJ_RAWTP:
		err = prepare_rawtp_ctx_specs(probe_id, inj, ctx_args);
		break;
	case INJ_TP:
		err = prepare_tp_ctx_specs(probe_id, inj, ctx_args);
		break;
	}

	if (err) {
		elog("Failed to prepare context data capture for injected probe '%s': %d\n",
		     desc, err);
		return err;
	}

	dlog("Probe '%s' ctx spec:", desc);

	for (i = 0; i < ctx_args->spec_cnt; i++) {
		const struct ctx_arg_spec *spec = &ctx_args->specs[i];
		enum ctxarg_kind kind = (spec->flags & CTXARG_KIND_MASK) >> CTXARG_KIND_SHIFT;
		const struct btf_type *t;
		int len = spec->flags & CTXARG_LEN_MASK, true_len;
		int off = (spec->flags & CTXARG_OFF_MASK) >> CTXARG_OFF_SHIFT;

		dlog(" %s=(", spec->name);

		switch (kind) {
		case CTXARG_KIND_VALUE:
			dlog("off=%d,len=%d", off, len);
			break;
		case CTXARG_KIND_PTR_FIXED:
			t = btf__type_by_id(ctx_args->btf, spec->pointee_btf_id);
			true_len = t->size;
			dlog("->id=%d,off=%d,len=%d(%d)", spec->pointee_btf_id,
			     off, true_len, len);
			break;
		case CTXARG_KIND_PTR_STR:
			dlog("->str,off=%d,len=str(%d)", off, len);
			break;
		case CTXARG_KIND_TP_VARLEN:
			dlog("->varlen,off=%d,len=varlen(%d)", off, len);
			break;
		default:
			dlog("???,off=%d,len=%d", off, len);
		}

		dlog(",btf_id=%d)", spec->btf_id);
	}

	dlog("\n");


	return 0;
}

__attribute__((destructor))
static void fn_args_cleanup(void)
{
	free(fn_infos);
	kmem_reader_bpf__destroy(kmem_skel);
}
