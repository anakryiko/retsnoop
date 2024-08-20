// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2024 Meta Platforms, Inc. */
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/btf.h>
#include <linux/ptrace.h>
#include "env.h"
#include "mass_attacher.h"
#include "utils.h"
#include "logic.h"
#include "hashmap.h"
#include "retsnoop.h"

static struct func_args_info *fn_infos;
static int fn_info_cnt, fn_info_cap;

const struct func_args_info *func_args_info(int func_id)
{
	return &fn_infos[func_id];
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
#else
static bool is_arg_in_reg(int arg_idx, const char **reg_name)
{
	*reg_name = "<unsupported>";
	return false;
}
#endif

static int realign_stack_off(int stack_off)
{
	return (stack_off + 7) / 8 * 8;
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
	int stack_off = 8; /* 8 bytes for return address */
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

int handle_func_args_capture(struct ctx *ctx, struct session *sess,
			     const struct func_args_capture *r)
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

static void fmt_capture_item(struct fmt_buf *b, const struct btf *btf, int btf_id,
			     void *data, size_t data_len, int indent_shift)
{
	struct btf_data_dump_opts opts = {};
	int err;

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

	err = btf_data_dump(btf, btf_id, data, data_len, btf_data_dump_printf, b, &opts);
	if (err == -E2BIG) {
		/* truncated data */
		bnappendf(b, "\u2026");
	} else if (err < 0) {
		/* unexpected error */
		const char *errstr = err_to_str(err);

		if (errstr)
			bnappendf(b, "...DUMP ERR=-%s...", errstr);
		else
			bnappendf(b, "...DUMP ERR=%d...", err);
	}
}

static void fmt_fnargs_item(struct fmt_buf *b,
			   const struct func_args_info *fn_args,
			   const struct func_arg_spec *spec,
			   void *data, size_t data_len, int indent_shift)
{
	if (!fn_args->btf) {
		char buf[32];

		/* fallback "raw registers" mode, data_len should be 8 */
		snprintf_smart_uint(buf, sizeof(buf), *(long long *)data);
		bnappendf(b, "%s", buf);

		return;
	}

	if (spec->pointee_btf_id < 0) {
		/* variable-length string */
		sanitize_string(data, data_len);
		bnappendf(b, "'%s'", (char *)data);
		return;
	}

	if (spec->pointee_btf_id) /* append pointer mark */
		bnappendf(b, "&");

	fmt_capture_item(b, fn_args->btf, spec->pointee_btf_id ?: spec->btf_id,
			 data, data_len, indent_shift);
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
		int width_lim = env.args_fmt_max_arg_width, vararg_n;
		struct fmt_buf b;
		bool is_vararg, has_ptr;

		has_ptr = fai->arg_ptrs & (1 << i);

		kind = (fn_args->arg_specs[i].arg_flags & FNARGS_KIND_MASK) >> FNARGS_KIND_SHIFT;
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
			fprintf(f, "\n%*.s\u203A ", indent_shift, "");
		if (fn_args->btf) {
			if (is_vararg)
				fprintf(f, "vararg%d%s=%s", i - vararg_start_idx, sep, sep);
			else
				fprintf(f, "%s%s=%s", fn_args->arg_specs[i].name, sep, sep);
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
			switch (fn_args->arg_specs[i].arg_flags & FNARGS_REGIDX_MASK) {
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
			fmt_fnargs_item(&b, fn_args, &fn_args->arg_specs[i],
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

void emit_ctx_data(FILE *f, struct stack_item *s, int indent_shift,
		   const struct inj_probe_info *inj,
		   const struct ctx_capture_item *cci)
{
	const char *sep = env.args_fmt_mode == ARGS_FMT_COMPACT ? "" : " ";
	int width_lim = env.args_fmt_max_arg_width;
	struct fmt_buf b;

	/* verbose args output mode doesn't have width limit */
	if (env.args_fmt_mode == ARGS_FMT_VERBOSE)
		width_lim = 0;
	b = FMT_FILE(f, s->src, width_lim);

	if (env.args_fmt_mode != ARGS_FMT_COMPACT)
		/* emit Unicode's slightly smaller-sized '>' as a marker of an argument */
		fprintf(f, "\n%*.s\u203A ", indent_shift, "");

	if (!inj->btf || inj->ctx_btf_id <= 0) {
		fprintf(f, "... missing BTF information ...");
		goto print_ellipsis;
	}

	fprintf(f, "%s%s=%s", "regs", sep, sep);

	if (cci->data_len < 0) {
		const char *errstr = err_to_str(cci->data_len);

		if (errstr)
			bnappendf(&b, "<ERR:-%s>", errstr);
		else
			bnappendf(&b, "<ERR:%d>", cci->data_len);

		goto print_ellipsis;
	}

	fmt_capture_item(&b, inj->btf, inj->ctx_btf_id, cci->data, cci->data_len, indent_shift);

print_ellipsis:
	/* append Unicode horizontal ellipsis (single-character triple dots)
	 * if output was truncated to mark its truncation visually
	 */
	if (width_lim && b.sublen > b.max_sublen)
		fprintf(f, "%s", UNICODE_HELLIP);
}

int handle_ctx_capture(struct ctx *ctx, struct session *sess, const struct ctx_capture *r)
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
	d->data = malloc(r->data_len);
	if (!d->data)
		return -ENOMEM;
	memcpy(d->data, r->data, r->data_len);

	sess->ctx_cnt++;

	return 0;
}

__attribute__((destructor))
static void fn_args_cleanup(void)
{
	free(fn_infos);
}
