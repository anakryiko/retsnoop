/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2021 Facebook */
#ifndef __MASS_ATTACHER_H
#define __MASS_ATTACHER_H

#include <stdbool.h>
#include <stddef.h>

struct btf;
struct bpf_link;
struct mass_attacher;
struct SKEL_NAME;

typedef bool (*func_filter_fn)(const struct mass_attacher *att,
			       const struct btf *btf, int func_btf_id,
			       const char *name, int func_id);

struct mass_attacher_func_info {
	const char *name;
	long addr;
	long size;
	int arg_cnt;
	int btf_id;

	int fentry_prog_fd;
	int fexit_prog_fd;

	struct bpf_link *kentry_link;
	struct bpf_link *kexit_link;
};

struct mass_attacher_opts {
	int max_func_cnt;
	int max_fileno_rlimit;
	bool verbose;
	bool debug;
	bool debug_extra;
	bool use_kprobes;
	func_filter_fn func_filter;
};

struct mass_attacher *mass_attacher__new(struct SKEL_NAME *skel, struct mass_attacher_opts *opts);
void mass_attacher__free(struct mass_attacher *att);

int mass_attacher__allow_glob(struct mass_attacher *att, const char *glob);
int mass_attacher__deny_glob(struct mass_attacher *att, const char *glob);

int mass_attacher__prepare(struct mass_attacher *att);
int mass_attacher__load(struct mass_attacher *att);
int mass_attacher__attach(struct mass_attacher *att);
void mass_attacher__activate(struct mass_attacher *att);

size_t mass_attacher__func_cnt(const struct mass_attacher *att);
const struct mass_attacher_func_info * mass_attacher__func(const struct mass_attacher *att, int id);
const struct btf *mass_attacher__btf(const struct mass_attacher *att);

/* Probably should be in some utils.h */
bool glob_matches(const char *glob, const char *s);

#endif /* __MASS_ATTACHER_H */
