// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2024 Meta Platforms, Inc. */
/*
 * This code is derived from libbpf's btf_dump__dump_type_data() API
 * implementation. But heavily tuned for retsnoop's needs and style.
 */

#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <bpf/btf.h>
#include "utils.h"

struct data_dumper {
	const struct btf *btf;
	const void *data;
	const void *data_end;
	size_t data_sz;
	struct btf_data_dump_opts opts;
	ddump_printf_fn printf_fn;
	void *printf_ctx;

	int ptr_sz;
	int depth;
	bool is_array_member;
	bool is_array_terminated;
	bool is_array_char;
};

static int ddump_emit_data(struct data_dumper *d,
			   const char *fname,
			   const struct btf_type *t, int id,
			   const void *data,
			   int bit_off, int bit_sz);

static void ddump_printf(const struct data_dumper *d, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	d->printf_fn(d->printf_ctx, fmt, args);
	va_end(args);
}

static const char *ddump_newline(struct data_dumper *d)
{
	return d->opts.compact || d->depth == 0 ? "" : "\n";
}

static const char *ddump_delim(struct data_dumper *d)
{
	return d->depth == 0 ? "" : ",";
}

static void ddump_emit_pfx(struct data_dumper *d)
{
	int i, lvl = d->opts.indent_level + d->depth;

	if (d->opts.compact)
		return;

	for (i = 0; i < lvl; i++)
		ddump_printf(d, "%s", d->opts.indent_str);
}

/* A macro is used here as ddump_emitf() appends format specifiers
 * to the format specifier passed in; these do the work of appending
 * delimiters etc while the caller simply has to specify the type values
 * in the format specifier + value(s).
 */
#define ddump_emitf(d, fmt, ...) \
	ddump_printf(d, fmt "%s%s", ##__VA_ARGS__, ddump_delim(d), ddump_newline(d))

static int ddump_unsupp_data(struct data_dumper *d, const struct btf_type *t, int id)
{
	ddump_printf(d, "<unsupp kind:%u>", btf_kind(t));
	return -ENOTSUP;
}

static int ddump_value_bitfield(struct data_dumper *d,
				const struct btf_type *t,
			        const void *data, int bit_off, int bit_sz,
				__u64 *value)
{
	int left_shift_bits, right_shift_bits;
	const __u8 *bytes = data;
	int nr_copy_bits;
	__u64 num = 0;
	int i;

	/* Maximum supported bitfield size is 64 bits */
	if (t->size > 8) {
		elog("unexpected bitfield size %d\n", t->size);
		return -EINVAL;
	}

	/* Bitfield value retrieval is done in two steps; first relevant bytes are
	 * stored in num, then we left/right shift num to eliminate irrelevant bits.
	 */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	for (i = t->size - 1; i >= 0; i--)
		num = num * 256 + bytes[i];
	nr_copy_bits = bit_sz + bit_off;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	for (i = 0; i < t->size; i++)
		num = num * 256 + bytes[i];
	nr_copy_bits = t->size * 8 - bit_off;
#else
# error "Unrecognized __BYTE_ORDER__"
#endif
	left_shift_bits = 64 - nr_copy_bits;
	right_shift_bits = 64 - bit_sz;

	*value = (num << left_shift_bits) >> right_shift_bits;

	return 0;
}

static int ddump_check_zero_bitfield(struct data_dumper *d,
				     const struct btf_type *t,
				     const void *data,
				     int bit_off, int bit_sz)
{
	__u64 check_num;
	int err;

	err = ddump_value_bitfield(d, t, data, bit_off, bit_sz, &check_num);
	if (err)
		return err;
	if (check_num == 0)
		return -ENODATA;
	return 0;
}

static int ddump_emit_bitfield(struct data_dumper *d, const struct btf_type *t,
			       const void *data, int bit_off, int bit_sz)
{
	bool is_signed = btf_int_encoding(t) & BTF_INT_SIGNED;
	__u64 value;
	char buf[32];
	int err;

	err = ddump_value_bitfield(d, t, data, bit_off, bit_sz, &value);
	if (err)
		return err;

	if (is_signed)
		snprintf_smart_int(buf, sizeof(buf), (long long)value);
	else
		snprintf_smart_uint(buf, sizeof(buf), value);
	ddump_emitf(d, "%s", buf);

	return 0;
}

/* ints, floats and ptrs */
static int ddump_check_zero_base_type(struct data_dumper *d,
				      const struct btf_type *t, int id,
				      const void *data)
{
	static __u8 bytecmp[16] = {};
	int nr_bytes;

	/* For pointer types, pointer size is not defined on a per-type basis.
	 * On dump creation however, we store the pointer size.
	 */
	if (btf_kind(t) == BTF_KIND_PTR)
		nr_bytes = d->ptr_sz;
	else
		nr_bytes = t->size;

	if (nr_bytes < 1 || nr_bytes > 16) {
		elog("unexpected size %d for id [%u]\n", nr_bytes, id);
		return -EINVAL;
	}

	if (memcmp(data, bytecmp, nr_bytes) == 0)
		return -ENODATA;
	return 0;
}

static bool ptr_is_aligned(const struct btf *btf, int type_id, const void *data)
{
	int alignment = btf__align_of(btf, type_id);

	if (alignment == 0)
		return false;

	return ((uintptr_t)data) % alignment == 0;
}

static int ddump_emit_int(struct data_dumper *d,
			  const struct btf_type *t, int type_id,
			  const void *data, int bit_off)
{
	int encoding = btf_int_encoding(t);
	bool sign = encoding & BTF_INT_SIGNED;
	char buf[32] __attribute__((aligned(16)));
	int buf_sz = sizeof(buf), sz = t->size;

	if (sz == 0 || sz > sizeof(buf)) {
		elog("unexpected size %d for id [%u]\n", sz, type_id);
		return -EINVAL;
	}

	/* handle packed int data - accesses of integers not aligned on
	 * int boundaries can cause problems on some platforms.
	 */
	if (!ptr_is_aligned(d->btf, type_id, data)) {
		memcpy(buf, data, sz);
		data = buf;
	}

	switch (sz) {
	case 16: {
		const __u64 *ints = data;
		__u64 lsi, msi;

		/* avoid use of __int128 as some 32-bit platforms do not
		 * support it.
		 */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		lsi = ints[0];
		msi = ints[1];
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
		lsi = ints[1];
		msi = ints[0];
#else
# error "Unrecognized __BYTE_ORDER__"
#endif
		if (msi == 0)
			ddump_emitf(d, "0x%llx", (unsigned long long)lsi);
		else
			ddump_emitf(d, "0x%llx%016llx",
				     (unsigned long long)msi,
				     (unsigned long long)lsi);
		break;
	}
	case 8:
		if (sign)
			snprintf_smart_int(buf, buf_sz, *(long long *)data);
		else
			snprintf_smart_uint(buf, buf_sz, *(unsigned long long *)data);
		ddump_emitf(d, "%s", buf);
		break;
	case 4:
		if (sign)
			snprintf_smart_int(buf, buf_sz, *(__s32 *)data);
		else
			snprintf_smart_uint(buf, buf_sz, *(__u32 *)data);
		ddump_emitf(d, "%s", buf);
		break;
	case 2:
		if (sign)
			snprintf_smart_int(buf, buf_sz, *(__s16 *)data);
		else
			snprintf_smart_uint(buf, buf_sz, *(__u16 *)data);
		ddump_emitf(d, "%s", buf);
		break;
	case 1:
		if (d->is_array_char) {
			/* check for null terminator */
			if (d->is_array_terminated)
				break;
			if (*(char *)data == '\0') {
				ddump_emitf(d, "'\\0'");
				d->is_array_terminated = true;
				break;
			}
			if (isprint(*(char *)data)) {
				ddump_emitf(d, "'%c'", *(char *)data);
				break;
			}
		}
		if (sign)
			snprintf_smart_int(buf, buf_sz, *(__s8 *)data);
		else
			snprintf_smart_uint(buf, buf_sz, *(__u8 *)data);
		ddump_emitf(d, "%s", buf);
		break;
	default:
		elog("unexpected sz %d for id [%u]\n", sz, type_id);
		return -EINVAL;
	}
	return 0;
}

static int ddump_emit_float(struct data_dumper *d,
			    const struct btf_type *t, int type_id,
			    const void *data)
{
	const union float_union {
		long double ld;
		double d;
		float f;
	} *flp = data;
	union float_union fl;
	int sz = t->size;

	/* handle unaligned data; copy to local union */
	if (!ptr_is_aligned(d->btf, type_id, data)) {
		memcpy(&fl, data, sz);
		flp = &fl;
	}

	switch (sz) {
	case 16:
		ddump_emitf(d, "%Lf", flp->ld);
		break;
	case 8:
		ddump_emitf(d, "%lf", flp->d);
		break;
	case 4:
		ddump_emitf(d, "%f", flp->f);
		break;
	default:
		elog("unexpected size %d for id [%u]\n", sz, type_id);
		return -EINVAL;
	}
	return 0;
}

static int ddump_emit_array(struct data_dumper *d,
			    const struct btf_type *t, int id,
			    const void *data)
{
	const struct btf_array *array = btf_array(t);
	const struct btf_type *elem_type;
	int i, elem_type_id;
	__s64 elem_size;
	bool is_array_member;
	bool is_array_terminated;

	elem_type_id = array->type;
	elem_type = btf_strip_mods_and_typedefs(d->btf, elem_type_id, NULL);
	elem_size = btf__resolve_size(d->btf, elem_type_id);
	if (elem_size <= 0) {
		elog("unexpected elem size %zd for array type [%u]\n", (ssize_t)elem_size, id);
		return -EINVAL;
	}

	if (btf_is_int(elem_type)) {
		/*
		 * BTF_INT_CHAR encoding never seems to be set for
		 * char arrays, so if size is 1, type name is "char", and
		 * element is printable as a char, we'll do that.
		 */
		if (elem_size == 1 &&
		    strcmp(btf__name_by_offset(d->btf, elem_type->name_off), "char") == 0)
			d->is_array_char = true;
	}

	/* note that we increment depth before calling ddump_printf() below;
	 * this is intentional. ddump_newline() will not print a
	 * newline for depth 0 (since this leaves us with trailing newlines
	 * at the end of typed display), so depth is incremented first.
	 * For similar reasons, we decrement depth before showing the closing
	 * parenthesis.
	 */
	d->depth++;
	ddump_printf(d, "[%s", ddump_newline(d));

	/* may be a multidimensional array, so store current "is array member"
	 * status so we can restore it correctly later.
	 */
	is_array_member = d->is_array_member;
	d->is_array_member = true;
	is_array_terminated = d->is_array_terminated;
	d->is_array_terminated = false;
	for (i = 0; i < array->nelems; i++, data += elem_size) {
		if (d->is_array_terminated)
			break;
		ddump_emit_data(d, NULL, elem_type, elem_type_id, data, 0, 0);
	}
	d->is_array_member = is_array_member;
	d->is_array_terminated = is_array_terminated;
	d->depth--;
	ddump_emit_pfx(d);
	ddump_emitf(d, "]");

	return 0;
}

static int ddump_emit_struct(struct data_dumper *d,
			     const struct btf_type *t, int id,
			     const void *data)
{
	const struct btf_member *m = btf_members(t);
	int n = btf_vlen(t), i, err = 0;

	/* note that we increment depth before calling ddump_printf() below;
	 * this is intentional. ddump_data_newline() will not print a
	 * newline for depth 0 (since this leaves us with trailing newlines
	 * at the end of typed display), so depth is incremented first.
	 * For similar reasons, we decrement depth before showing the closing
	 * parenthesis.
	 */
	d->depth++;
	ddump_printf(d, "{%s", ddump_newline(d));

	for (i = 0; i < n; i++, m++) {
		const struct btf_type *mtype;
		const char *mname;
		int moffset;
		int bit_sz;

		mtype = btf__type_by_id(d->btf, m->type);
		mname = btf__name_by_offset(d->btf, m->name_off);
		moffset = btf_member_bit_offset(t, i);

		bit_sz = btf_member_bitfield_size(t, i);
		err = ddump_emit_data(d, mname, mtype, m->type,
				      data + moffset / 8, moffset % 8, bit_sz);
		if (err < 0)
			return err;
	}
	d->depth--;
	ddump_emit_pfx(d);
	ddump_emitf(d, "}");
	return err;
}

static int ddump_emit_ptr(struct data_dumper *d,
			  const struct btf_type *t, int id,
			  const void *data)
{
	if (ptr_is_aligned(d->btf, id, data) && d->ptr_sz == sizeof(void *)) {
		ddump_emitf(d, "%p", *(void **)data);
	} else {
		union {
			unsigned int p;
			unsigned long long lp;
		} pt;

		memcpy(&pt, data, d->ptr_sz);
		if (d->ptr_sz == 4)
			ddump_emitf(d, "0x%x", pt.p);
		else
			ddump_emitf(d, "0x%llx", pt.lp);
	}
	return 0;
}

static int ddump_value_enum(struct data_dumper *d,
			    const struct btf_type *t, int id,
			    const void *data, __s64 *value)
{
	bool is_signed = btf_kflag(t);

	if (!ptr_is_aligned(d->btf, id, data)) {
		__u64 val;
		int err;

		err = ddump_value_bitfield(d, t, data, 0, 0, &val);
		if (err)
			return err;
		*value = (__s64)val;
		return 0;
	}

	switch (t->size) {
	case 8:
		*value = *(__s64 *)data;
		return 0;
	case 4:
		*value = is_signed ? (__s64)*(__s32 *)data : *(__u32 *)data;
		return 0;
	case 2:
		*value = is_signed ? *(__s16 *)data : *(__u16 *)data;
		return 0;
	case 1:
		*value = is_signed ? *(__s8 *)data : *(__u8 *)data;
		return 0;
	default:
		elog("unexpected size %d for enum, id:[%u]\n", t->size, id);
		return -EINVAL;
	}
}

static int ddump_emit_enum(struct data_dumper *d,
			   const struct btf_type *t, int id,
			   const void *data)
{
	bool is_signed;
	__s64 value;
	int i, err;

	err = ddump_value_enum(d, t, id, data, &value);
	if (err)
		return err;

	is_signed = btf_kflag(t);
	if (btf_is_enum(t)) {
		const struct btf_enum *e;

		for (i = 0, e = btf_enum(t); i < btf_vlen(t); i++, e++) {
			if (value != e->val)
				continue;
			ddump_emitf(d, "%s", btf__name_by_offset(d->btf, e->name_off));
			return 0;
		}

		ddump_emitf(d, is_signed ? "%d" : "%u", value);
	} else {
		const struct btf_enum64 *e;
		char buf[32];

		for (i = 0, e = btf_enum64(t); i < btf_vlen(t); i++, e++) {
			if (value != btf_enum64_value(e))
				continue;
			ddump_emitf(d, "%s", btf__name_by_offset(d->btf, e->name_off));
			return 0;
		}

		if (is_signed)
			snprintf_smart_int(buf, sizeof(buf), value);
		else
			snprintf_smart_uint(buf, sizeof(buf), (unsigned long long)value);

		ddump_emitf(d, is_signed ? "%sLL" : "%sULL", buf);
	}
	return 0;
}

/* Return size of type, or if there is not enough data to cover entire base
 * type, return -E2BIG.
 */
static int ddump_check_enough_data(struct data_dumper *d,
				   const struct btf_type *t, int id,
				   const void *data,
				   int bit_off, int bit_sz)
{
	long size;

	if (bit_sz) {
		/* bit_off is at most 7. bit_sz is at most 128. */
		int nr_bytes = (bit_off + bit_sz + 7) / 8;

		/* When bit_sz is non zero, it is called from
		 * ddump_emit_struct() where it only cares about
		 * negative error value.
		 * Return nr_bytes in success case to make it
		 * consistent as the regular integer case below.
		 */
		return data + nr_bytes > d->data_end ? -E2BIG : nr_bytes;
	}

	size = btf__resolve_size(d->btf, id);
	if (size < 0 || size >= INT_MAX) {
		elog("unexpected size [%zd] for id [%u]\n", (ssize_t)size, id);
		return -EINVAL;
	}

	/* Only do overflow checking for base types; we do not want to
	 * avoid showing part of a struct, union or array, even if we
	 * do not have enough data to show the full object.
	 * By restricting overflow checking to base types we can ensure
	 * that partial display succeeds, while avoiding overflowing
	 * and using bogus data for display.
	 */
	t = btf_strip_mods_and_typedefs(d->btf, id, NULL);
	switch (btf_kind(t)) {
	case BTF_KIND_INT:
	case BTF_KIND_FLOAT:
	case BTF_KIND_PTR:
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64:
		if (data + (bit_off + size * 8 + 7) / 8 > d->data_end)
			return -E2BIG;
		break;
	default:
		break;
	}
	return size;
}

static int ddump_check_zeros(struct data_dumper *d,
			     const struct btf_type *t, int id,
			     const void *data,
			     int bit_off, int bit_sz)
{
	__s64 value;
	int i, err;

	/* toplevel exceptions; we show zero values if
	 * - we ask for them (emit_zeros)
	 * - if we are at top-level so we see "struct empty { }"
	 * - or if we are an array member and the array is non-empty and
	 *   not a char array; we don't want to be in a situation where we
	 *   have an integer array 0, 1, 0, 1 and only show non-zero values.
	 *   If the array contains zeroes only, or is a char array starting
	 *   with a '\0', the array-level check_zero() will prevent showing it;
	 *   we are concerned with determining zero value at the array member
	 *   level here.
	 */
	if (d->opts.emit_zeroes || d->depth == 0 || (d->is_array_member && !d->is_array_char))
		return 0;

	t = btf_strip_mods_and_typedefs(d->btf, id, NULL);
	switch (btf_kind(t)) {
	case BTF_KIND_INT:
		if (bit_sz)
			return ddump_check_zero_bitfield(d, t, data, bit_off, bit_sz);
		return ddump_check_zero_base_type(d, t, id, data);
	case BTF_KIND_FLOAT:
	case BTF_KIND_PTR:
		return ddump_check_zero_base_type(d, t, id, data);
	case BTF_KIND_ARRAY: {
		const struct btf_array *array = btf_array(t);
		const struct btf_type *elem_type;
		__u32 elem_type_id, elem_size;
		bool is_char;

		elem_type_id = array->type;
		elem_size = btf__resolve_size(d->btf, elem_type_id);
		elem_type = btf_strip_mods_and_typedefs(d->btf, elem_type_id, NULL);

		is_char = btf_is_int(elem_type) && elem_size == 1;

		/* check all elements; if _any_ element is nonzero, all
		 * of array is displayed. We make an exception however
		 * for char arrays where the first element is 0; these
		 * are considered zeroed also, even if later elements are
		 * non-zero because the string is terminated.
		 */
		for (i = 0; i < array->nelems; i++) {
			if (i == 0 && is_char && *(char *)data == 0)
				return -ENODATA;
			err = ddump_check_zeros(d, elem_type, elem_type_id,
						data + (i * elem_size), bit_off, 0);
			if (err != -ENODATA)
				return err;
		}
		return -ENODATA;
	}
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION: {
		const struct btf_member *m = btf_members(t);
		int n = btf_vlen(t);

		/* if any struct/union member is non-zero, the struct/union
		 * is considered non-zero and dumped.
		 */
		for (i = 0; i < n; i++, m++) {
			const struct btf_type *mtype;
			int moffset;

			mtype = btf__type_by_id(d->btf, m->type);
			moffset = btf_member_bit_offset(t, i);

			/* btf_int_bits() does not store member bitfield size;
			 * bitfield size needs to be stored here so int display
			 * of member can retrieve it.
			 */
			bit_sz = btf_member_bitfield_size(t, i);
			err = ddump_check_zeros(d, mtype, m->type,
						data + moffset / 8, moffset % 8, bit_sz);
			if (err != ENODATA)
				return err;
		}
		return -ENODATA;
	}
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64:
		err = ddump_value_enum(d, t, id, data, &value);
		if (err)
			return err;
		if (value == 0)
			return -ENODATA;
		return 0;
	default:
		return 0;
	}
}

/* returns size of data dumped, or error. */
static int ddump_emit_data(struct data_dumper *d,
			   const char *fname,
			   const struct btf_type *t, int id,
			   const void *data,
			   int bit_off, int bit_sz)
{
	int size, err = 0;

	size = ddump_check_enough_data(d, t, id, data, bit_off, bit_sz);
	if (size < 0)
		return size;
	err = ddump_check_zeros(d, t, id, data, bit_off, bit_sz);
	if (err) {
		/* zeroed data is expected and not an error, so simply skip
		 * dumping such data.  Record other errors however.
		 */
		if (err == -ENODATA)
			return size;
		return err;
	}
	ddump_emit_pfx(d);

	if (!d->opts.skip_names && fname && strlen(fname) > 0)
		ddump_printf(d, ".%s = ", fname);

	t = btf_strip_mods_and_typedefs(d->btf, id, NULL);

	switch (btf_kind(t)) {
	case BTF_KIND_UNKN:
	case BTF_KIND_FWD:
	case BTF_KIND_FUNC:
	case BTF_KIND_FUNC_PROTO:
	case BTF_KIND_DECL_TAG:
	case BTF_KIND_VAR:
	case BTF_KIND_DATASEC:
		err = ddump_unsupp_data(d, t, id);
		break;
	case BTF_KIND_INT:
		if (bit_sz)
			err = ddump_emit_bitfield(d, t, data, bit_off, bit_sz);
		else
			err = ddump_emit_int(d, t, id, data, bit_off);
		break;
	case BTF_KIND_FLOAT:
		err = ddump_emit_float(d, t, id, data);
		break;
	case BTF_KIND_PTR:
		err = ddump_emit_ptr(d, t, id, data);
		break;
	case BTF_KIND_ARRAY:
		err = ddump_emit_array(d, t, id, data);
		break;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		err = ddump_emit_struct(d, t, id, data);
		break;
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64:
		/* handle bitfield and int enum values */
		if (bit_sz) {
			__u64 print_num;
			__s64 enum_val;

			err = ddump_value_bitfield(d, t, data, bit_off, bit_sz, &print_num);
			if (err)
				break;
			enum_val = (__s64)print_num;
			err = ddump_emit_enum(d, t, id, &enum_val);
		} else
			err = ddump_emit_enum(d, t, id, data);
		break;
	default:
		elog("unexpected kind [%u] for id [%u]\n", BTF_INFO_KIND(t->info), id);
		return -EINVAL;
	}
	if (err < 0)
		return err;
	return size;
}

int btf_data_dump(const struct btf *btf, int id,
		  const void *data, size_t data_sz,
		  ddump_printf_fn printf_fn, void *ctx,
		  const struct btf_data_dump_opts *opts)
{
	struct data_dumper d;
	const struct btf_type *t;

	d.btf = btf;
	d.data = data;
	d.data_end = data + data_sz;
	d.data_sz = data_sz;
	d.opts = *opts;

	d.printf_fn = printf_fn;
	d.printf_ctx = ctx;

	d.ptr_sz = sizeof(void *);

	/* default indent string is a tab */
	if (!d.opts.indent_str)
		d.opts.indent_str = "\t";

	t = btf__type_by_id(btf, id);
	if (!t)
		return -ENOENT;

	return ddump_emit_data(&d, NULL, t, id, data, 0, 0);
}
