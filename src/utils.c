// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "utils.h"

/* adapted from libbpf sources */
bool glob_matches(const char *glob, const char *s)
{
	while (*s && *glob && *glob != '*') {
		/* Matches any single character */
		if (*glob == '?') {
			s++;
			glob++;
			continue;
		}
		if (*s != *glob)
			return false;
		s++;
		glob++;
	}
	/* Check wild card */
	if (*glob == '*') {
		while (*glob == '*') {
			glob++;
		}
		if (!*glob) /* Tail wild card matches all */
			return true;
		while (*s) {
			if (glob_matches(glob, s++))
				return true;
		}
	}
	return !*s && !*glob;
}

bool full_glob_matches(const char *name_glob, const char *mod_glob,
		       const char *name, const char *mod)
{
	if (!mod_glob)
		return glob_matches(name_glob, name);

	if (!mod)
		return false;

	return glob_matches(name_glob, name) && glob_matches(mod_glob, mod);
}

int append_str(char ***strs, int *cnt, const char *str)
{
	void *tmp;
	char *s;

	tmp = realloc(*strs, (*cnt + 1) * sizeof(**strs));
	if (!tmp)
		return -ENOMEM;
	*strs = tmp;

	(*strs)[*cnt] = s = strdup(str);
	if (!s)
		return -ENOMEM;

	*cnt = *cnt + 1;
	return 0;
}

int append_str_file(char ***strs, int *cnt, const char *file)
{
	char buf[256];
	FILE *f;
	int err = 0;

	f = fopen(file, "r");
	if (!f) {
		err = -errno;
		fprintf(stderr, "Failed to open '%s': %d\n", file, err);
		return err;
	}

	while (fscanf(f, "%s", buf) == 1) {
		if (append_str(strs, cnt, buf)) {
			err = -ENOMEM;
			goto cleanup;
		}
	}

cleanup:
	fclose(f);
	return err;
}

int append_glob(struct glob **globs, int *cnt, const char *str)
{
	struct glob *g;
	char name[128], mod[128];
	void *tmp;

	tmp = realloc(*globs, (*cnt + 1) * sizeof(**globs));
	if (!tmp)
		return -ENOMEM;
	*globs = tmp;

	g = &(*globs)[*cnt];
	if (sscanf(str, "%127[^[ ] [%127[^]]]", name, mod) == 2) {
		g->name = strdup(name);
		g->mod = strdup(mod);
		if (!g->name || !g->mod) {
			free(g->name);
			free(g->mod);
			return -ENOMEM;
		}
	} else {
		g->name = strdup(str);
		g->mod = NULL;
		if (!g->name)
			return -ENOMEM;
	}

	*cnt = *cnt + 1;
	return 0;
}

int append_glob_file(struct glob **globs, int *cnt, const char *file)
{
	char buf[256];
	FILE *f;
	int err = 0;

	f = fopen(file, "r");
	if (!f) {
		err = -errno;
		fprintf(stderr, "Failed to open '%s': %d\n", file, err);
		return err;
	}

	while (fscanf(f, "%s", buf) == 1) {
		if (append_glob(globs, cnt, buf)) {
			err = -ENOMEM;
			goto cleanup;
		}
	}

cleanup:
	fclose(f);
	return err;
}

int append_compile_unit(struct addr2line *a2l, struct glob **globs, int *cnt, const char *cu)
{
	int err = 0;
	struct a2l_cu_resp *cu_resps = NULL;
	int resp_cnt;
	int i;

	resp_cnt = addr2line__query_symbols(a2l, cu, &cu_resps);
	if (resp_cnt < 0) {
		return resp_cnt;
	}

	for (i = 0; i < resp_cnt; i++) {
		if (append_glob(globs, cnt, cu_resps[i].fname)) {
			err = -ENOMEM;
			break;
		}
	}

	free(cu_resps);
	return err;
}
