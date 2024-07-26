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
	const struct btf_param *p;
	const struct btf_type *fn_t, *t;
	int i, n, reg_idx = 0;
	int stack_off = 8; /* 8 bytes for return address */

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
			spec->arg_flags = FUNC_ARG_REG | 8;
			spec->arg_flags |= i << FUNC_ARG_REGIDX_SHIFT;

			dlog(" arg#%d=%s", i, reg_name);
		}
		dlog(" (NO BTF INFO)\n");
		return 0;
	}

	fn_t = btf__type_by_id(finfo->btf, finfo->btf_id); /* FUNC */
	fn_t = btf__type_by_id(finfo->btf, fn_t->type); /* FUNC_PROTO */

	n = btf_vlen(fn_t);
	if (n > MAX_FNARGS_ARG_SPEC_CNT)
		n = MAX_FNARGS_ARG_SPEC_CNT;

	fn_args->arg_spec_cnt = n;

	for (i = 0; i < n; i++) {
		int btf_id, data_len, true_len;
		const char *reg1_name, *reg2_name;

		p = btf_params(fn_t) + i;
		spec = &fn_args->arg_specs[i];

		spec->name = btf__name_by_offset(finfo->btf, p->name_off);
		spec->btf_id = p->type;
		spec->pointee_btf_id = 0;

		if (spec->btf_id == 0) {
			/* we don't know what to do with vararg argument */
			dlog(" (vararg)");
			spec->btf_id = 0;
			/* keep arg_flags non-zero, but don't set any of
			 * {REG, REG_PAIR, STACK} flags; BPF side will
			 * just skip this arg
			 */
			spec->arg_flags = FUNC_ARG_VARARG;
			continue;
		}

		dlog(" %s=(", spec->name);

		t = btf_strip_mods_and_typedefs(finfo->btf, spec->btf_id, &btf_id);
		if (btf_is_fixed_sized(finfo->btf, t) || btf_is_ptr(t)) {
			true_len = btf_is_ptr(t) ? 8 : t->size;
			data_len = min(true_len, env.args_max_sized_arg_size);

			if (true_len <= 8 && is_arg_in_reg(reg_idx, &reg1_name)) {
				/* fits in one register */
				spec->arg_flags = FUNC_ARG_REG | data_len;
				spec->arg_flags |= reg_idx << FUNC_ARG_REGIDX_SHIFT;
				dlog("%s", reg1_name);
				reg_idx += 1;
			} else if (true_len <= 16 &&
				   is_arg_in_reg(reg_idx, &reg1_name) &&
				   is_arg_in_reg(reg_idx + 1, &reg2_name)) {
				/* passed in a pair of registers */
				spec->arg_flags = FUNC_ARG_REG_PAIR | data_len;
				spec->arg_flags |= reg_idx << FUNC_ARG_REGIDX_SHIFT;
				reg_idx += 2;
				dlog("%s:%s", reg1_name, reg2_name);
			} else {
				/* passed on the stack */
				if (stack_off > FUNC_ARG_STACKOFF_MAX) {
					dlog("fp+%d(TOO LARGE!!!)", stack_off);
					stack_off = realign_stack_off(stack_off + true_len);
					spec->arg_flags = FUNC_ARG_STACKOFF_2BIG;
					goto skip_arg;
				} else {
					spec->arg_flags = FUNC_ARG_STACK | data_len;
					spec->arg_flags |= stack_off << FUNC_ARG_STACKOFF_SHIFT;
					dlog("fp+%d", stack_off);
					stack_off = realign_stack_off(stack_off + true_len);
				}
			}
		} else {
			/* unrecognized, read raw 8 byte value, assume single register */
			true_len = data_len = -1;
			dlog("!!!UNKNOWN ARG #%d KIND %d!!!", i, btf_kind(t));
			spec->arg_flags = FUNC_ARG_UNKN; /* skip it */
		}

		if (btf_is_ptr(t)) {
			dlog("->");

			spec->arg_flags &= ~FUNC_ARG_LEN_MASK;

			/* NOTE: we fill out spec->pointee_btf_id */
			t = btf_strip_mods_and_typedefs(finfo->btf, t->type, &spec->pointee_btf_id);
			if (btf_is_char(finfo->btf, t)) {
				/* varlen string */
				true_len = -1; /* mark that it's variable-length, for logging */
				data_len = env.args_max_str_arg_size;
				spec->arg_flags |= FUNC_ARG_PTR | FUNC_ARG_STR | data_len;
				spec->pointee_btf_id = -1; /* special string marker */
				dlog("str");
			} else if (btf_is_fixed_sized(finfo->btf, t)) {
				true_len = t->size;
				data_len = min(true_len, env.args_max_sized_arg_size);
				spec->arg_flags |= FUNC_ARG_PTR | data_len;
				dlog("ptr_id=%d", spec->pointee_btf_id);
			} else {
				/* generic pointer, treat as u64 */
				true_len = data_len = 8; /* sizeof(void *), assume 64-bit */
				spec->arg_flags |= data_len; /* NOTE: no FUNC_ARG_PTR flags */
				spec->pointee_btf_id = 0; /* raw pointer doesn't set pointee */
				dlog("raw");
			}
		}

skip_arg:
		if (data_len < 0) /* unknown */
			dlog(",len=??");
		else if (true_len < 0) /* variable-sized */
			dlog(",len=varlen(%d)", data_len);
		else if (true_len != data_len) /* truncated */
			dlog(",len=%d(%d)", true_len, data_len);
		else /* full data */
			dlog(",len=%d", data_len);

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

static void prepare_fn_arg(struct fmt_buf *b,
			   const struct func_args_info *fn_args,
			   const struct func_arg_spec *spec,
			   void *data, size_t data_len, int indent_shift)
{
	struct btf_data_dump_opts opts = {};
	int err;

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

	err = btf_data_dump(fn_args->btf, spec->pointee_btf_id ?: spec->btf_id,
			    data, data_len,
			    btf_data_dump_printf, b, &opts);
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

void emit_fnargs_data(FILE *f, struct stack_item *s, const struct func_args_item *fai,
		      int indent_shift)
{
	const struct func_args_info *fn_args = &fn_infos[fai->func_id];
	int i, len;
	void *data = fai->arg_data;
	const char *sep = env.args_fmt_mode == ARGS_FMT_VERBOSE ? " " : "";

	for (i = 0; i < fn_args->arg_spec_cnt; i++) {
		int width_lim = env.args_fmt_max_arg_width;
		struct fmt_buf b;

		/* verbose args output mode doesn't have width limit */
		if (env.args_fmt_mode == ARGS_FMT_VERBOSE)
			width_lim = 0;
		b = FMT_FILE(f, s->src, width_lim);

		if (env.args_fmt_mode == ARGS_FMT_COMPACT)
			fprintf(f, "%s", i == 0 ? "" : " ");
		else /* emit Unicode's slightly smaller-sized '>' as a marker of an argument */
			fprintf(f, "\n%*.s\u203A ", indent_shift, "");
		if (fn_args->btf)
			fprintf(f, "%s%s=%s", fn_args->arg_specs[i].name, sep, sep);
		else /* "raw" BTF-less mode */
			fprintf(f, "arg%d%s=%s", i, sep, sep);

		if (env.args_capture_raw_ptrs && (fai->arg_ptrs & (1 << i))) {
			bnappendf(&b, "(0x%llx)", *(long long *)data);
			data += 8;
		}

		len = fai->arg_lens[i];
		if (len == 0) {
			/* we encode special conditions in REGIDX mask */
			switch (fn_args->arg_specs[i].arg_flags & FUNC_ARG_REGIDX_MASK) {
			case FUNC_ARG_VARARG:
				bnappendf(&b, "(vararg)");
				break;
			case FUNC_ARG_UNKN:
				bnappendf(&b, "(unsupp)");
				break;
			case FUNC_ARG_STACKOFF_2BIG:
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
			prepare_fn_arg(&b, fn_args, &fn_args->arg_specs[i],
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

__attribute__((destructor))
static void fn_args_cleanup(void)
{
	free(fn_infos);
}
