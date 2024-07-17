/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2022 Meta Platforms, Inc. */
#ifndef __UTILS_H
#define __UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include "addr2line.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#define min(x, y) ((x) < (y) ? (x): (y))
#define max(x, y) ((x) < (y) ? (y): (x))

/* Macro to output glob or kprobe full display name in the form of either:
 *   - 'name', if mod is NULL;
 *   - 'name [mod]', if mod is not NULL;
 * printf() format string should have %s%s%s%s arguments
 * corresponding to NAME_MOD() "invocation"
 */
#define NAME_MOD(name, mod) name, mod ? " [" : "", mod ?: "", mod ? "]" : ""

#define snappendf(dst, fmt, args...)							\
	dst##_len += snprintf(dst + dst##_len,						\
			      sizeof(dst) < dst##_len ? 0 : sizeof(dst) - dst##_len,	\
			      fmt, ##args)

#define vsnappendf(dst, fmt, args)							\
	dst##_len += vsnprintf(dst + dst##_len,						\
			       sizeof(dst) < dst##_len ? 0 : sizeof(dst) - dst##_len,	\
			       fmt, args)

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

#endif /* __UTILS_H */
