/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2022 Meta Platforms, Inc. */
#ifndef __UTILS_H
#define __UTILS_H

#include <stdbool.h>
#include "addr2line.h"

struct glob {
	char *name;
	char *mod;
};

bool glob_matches(const char *glob, const char *s);
bool full_glob_matches(const char *name_glob, const char *mod_glob,
		       const char *name, const char *mod);

int append_str(char ***strs, int *cnt, const char *str);
int append_str_file(char ***strs, int *cnt, const char *file);

int append_glob(struct glob **globs, int *cnt, const char *str);
int append_glob_file(struct glob **globs, int *cnt, const char *file);

int append_compile_unit(struct addr2line *a2l, struct glob **globs, int *cnt, const char *cu);

#endif /* __UTILS_H */
