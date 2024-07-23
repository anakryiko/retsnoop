/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2022 Meta Platforms, Inc. */
#ifndef __UTILS_H
#define __UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <bpf/btf.h>
#include "addr2line.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#define min(x, y) ((x) < (y) ? (x): (y))
#define max(x, y) ((x) < (y) ? (y): (x))

/*
 * Logging helpers
 */

#ifndef elog
#define elog(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#endif

#ifndef log
#define log(fmt, ...) printf(fmt, ##__VA_ARGS__)
#endif
#ifndef vlog
#define vlog(fmt, ...) do { if (env.verbose) { printf(fmt, ##__VA_ARGS__); } } while (0)
#endif
#ifndef dlog
#define dlog(fmt, ...) do { if (env.debug) { printf(fmt, ##__VA_ARGS__); } } while (0)
#endif

/*
 * Formatting helpers
 */

/* Macro to output glob or kprobe full display name in the form of either:
 *   - 'name', if mod is NULL;
 *   - 'name [mod]', if mod is not NULL;
 * printf() format string should have %s%s%s%s arguments
 * corresponding to NAME_MOD() "invocation"
 */
#define NAME_MOD(name, mod) name, mod ? " [" : "", mod ?: "", mod ? "]" : ""

/* horizontal ellipsis (single-character Unicode triple dots) */
#define UNICODE_HELLIP "\u2026"

struct fmt_buf {
	FILE *f;
	char *buf;
	int sublen;
	int max_sublen;

	int *lenp;
};

/* Create sub-fmt_buf using *dst*'s full underlying buffer and taking into
 * account already emitted amount of data (stored in *dst##_len*). This
 * sub-buffer is allowed to accept at most *max_sublen* characters. If full
 * buffer has less space available, the remaining smaller space overrides
 * *max_sublen*.
 */
#define FMT_SUBBUF(dst, n) {								\
	.buf = (dst),									\
	.lenp = &(dst##_len),								\
	.max_sublen = min((n), sizeof(dst) < dst##_len ? 0 : sizeof(dst) - dst##_len),	\
	.sublen = 0,									\
}
/* File-based output with optional output limit (dst is used as temporary buf) */
#define FMT_FILE(file, dst, n) (struct fmt_buf){					\
	.f = (file),									\
	.buf = (dst),									\
	.lenp = &(dst##_len),								\
	.max_sublen = min((n), sizeof(dst) < dst##_len ? 0 : sizeof(dst) - dst##_len),	\
	.sublen = 0,									\
}

static inline ssize_t vbnappendf(struct fmt_buf *b, const char *fmt, va_list args)
{
	ssize_t n;

	if (b->f && b->max_sublen == 0) { /* unlimited file-based output */
		n = vfprintf(b->f, fmt, args);
		if (n < 0)
			return n;
	} else if (b->f) {
		/* we use buffer to format intermediate output and then honor specified
		 * max_sublen limit when outputting into file
		 */
		n = vsnprintf(b->buf + b->sublen,
			      b->sublen < b->max_sublen ? b->max_sublen - b->sublen : 0,
			      fmt, args);
		if (n < 0)
			return n;
		if (b->sublen < b->max_sublen)
			fprintf(b->f, "%s", b->buf + b->sublen);
	} else { /* buffer-based output */
		n = vsnprintf(b->buf + *b->lenp,
			      b->sublen < b->max_sublen ? b->max_sublen - b->sublen : 0,
			      fmt, args);
		if (n < 0)
			return n;
		if (b->sublen < b->max_sublen)
			*b->lenp += min(n, b->max_sublen - b->sublen - 1);
	}

	b->sublen += n;

	return n;
}

static inline ssize_t bnappendf(struct fmt_buf *b, const char *fmt, ...)
{
	va_list args;
	ssize_t n;

	va_start(args, fmt);
	n = vbnappendf(b, fmt, args);
	va_end(args);

	return n;
}

#define snappendf(dst, fmt, args...)							\
	dst##_len += snprintf(dst + dst##_len,						\
			      sizeof(dst) < dst##_len ? 0 : sizeof(dst) - dst##_len,	\
			      fmt, ##args)

#define vsnappendf(dst, fmt, args)							\
	dst##_len += vsnprintf(dst + dst##_len,						\
			       sizeof(dst) < dst##_len ? 0 : sizeof(dst) - dst##_len,	\
			       fmt, args)

int snprintf_smart_uint(char *buf, size_t buf_sz, unsigned long long value);
int snprintf_smart_int(char *buf, size_t buf_sz, long long value);

/*
 * Atomic helpers
 */

static inline void atomic_inc(long *value)
{
	(void)__atomic_add_fetch(value, 1, __ATOMIC_RELAXED);
}

static inline void atomic_add(long *value, long n)
{
	(void)__atomic_add_fetch(value, n, __ATOMIC_RELAXED);
}

static inline long atomic_load(long *value)
{
	return __atomic_load_n(value, __ATOMIC_RELAXED);
}

static inline long atomic_swap(long *value, long n)
{
	return __atomic_exchange_n(value, n, __ATOMIC_RELAXED);
}

/*
 * Errno helpers
 */

#define MAX_ERRNO 4095

int str_to_err(const char *arg);
const char *err_to_str(long err);

static inline void err_mask_set(uint64_t *err_mask, int err_value)
{
	err_mask[err_value / 64] |= 1ULL << (err_value % 64);
}

static inline bool is_err_in_mask(uint64_t *err_mask, int err)
{
	if (err < 0)
		err = -err;
	if (err > MAX_ERRNO)
		return false;
	return (err_mask[err / 64] >> (err % 64)) & 1;
}

/*
 * Time helpers
 */

static inline uint64_t timespec_to_ns(struct timespec *ts)
{
	return ts->tv_sec * 1000000000ULL + ts->tv_nsec;
}

static inline uint64_t now_ns(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);

	return timespec_to_ns(&t);
}

void ts_to_str(uint64_t ts, char buf[], size_t buf_sz);

extern uint64_t ktime_off;

void calibrate_ktime(void);

static inline uint64_t ktime_to_ts(uint64_t ktime_ts)
{
	return ktime_off + ktime_ts;
}

/*
 * Glob helpers
 */

struct glob {
	char *name;
	char *mod;
	bool mandatory;
};

bool glob_matches(const char *glob, const char *s);
bool full_glob_matches(const char *name_glob, const char *mod_glob,
		       const char *name, const char *mod);

int append_str(char ***strs, int *cnt, const char *str);
int append_str_file(char ***strs, int *cnt, const char *file);

int append_glob(struct glob **globs, int *cnt, const char *str, bool mandatory);
int append_glob_file(struct glob **globs, int *cnt, const char *file, bool mandatory);

int append_compile_unit(struct addr2line *a2l, struct glob **globs, int *cnt, const char *cu, bool mandatory);

int append_pid(int **pids, int *cnt, const char *arg);

enum glob_flags {
	GLOB_ALLOW = 0x1,
	GLOB_DENY = 0x2,
	/* implicitly added glob, this affects match logging verboseness
	 * (internal globs are not emitted in logs unless debug verboseness is
	 * requested)
	 */
	GLOB_INTERNAL = 0x4,
};

struct glob_spec {
	char *glob;
	char *mod_glob;
	int matches;
	enum glob_flags flags;
};

struct glob_set {
	struct glob_spec *globs;
	int glob_cnt;
};

int glob_set__add_glob(struct glob_set *gs,
		       const char *glob, const char *mod_glob,
		       enum glob_flags flags);
bool glob_set__match(const struct glob_set *gs, const char *name, const char *mod, int *glob_idx);
void glob_set__clear(struct glob_set *gs);

/*
 * BTF utils
 */

static inline const struct btf_type *btf_strip_mods_and_typedefs(const struct btf *btf,
								 int id, int *res_id)
{
	const struct btf_type *t;

	t = btf__type_by_id(btf, id);
	while (btf_is_mod(t) || btf_is_typedef(t)) {
		id = t->type;
		t = btf__type_by_id(btf, id);
	}
	if (res_id)
		*res_id = id;
	return t;
}

typedef void (*ddump_printf_fn)(void *ctx, const char *fmt, va_list args);

struct btf_data_dump_opts {
	/* indentation shift for all lines starting from the second, in spaces */
	int indent_shift;
	const char *indent_str;
	int indent_level;
	bool compact;		/* no newlines/indentation */
	bool skip_names;	/* skip member names */
	bool emit_zeroes;	/* show 0-valued fields */
};

int btf_data_dump(const struct btf *btf, int id,
		  const void *data, size_t data_sz,
		  ddump_printf_fn printf_fn, void *ctx,
		  const struct btf_data_dump_opts *opts);

#endif /* __UTILS_H */
