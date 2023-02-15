// SPDX-License-Identifier: BSD-2-Clause
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include "ksyms.h"

struct ksyms {
	struct ksym *syms;
	struct ksym **syms_by_kind_name;
	int syms_sz;
	int syms_cap;
	char *strs;
	int strs_sz;
	int strs_cap;
};

static int ksyms__add_symbol(struct ksyms *ksyms, const char *name, const char *mod,
			     unsigned long addr, char sym_type)
{
	size_t new_cap, name_len, mod_len;
	struct ksym *ksym;
	void *tmp;

	name_len = strlen(name) + 1;
	mod_len = mod ? strlen(mod) + 1 : 0;

	if (ksyms->strs_sz + name_len + mod_len > ksyms->strs_cap) {
		new_cap = ksyms->strs_cap * 4 / 3;
		if (new_cap < ksyms->strs_sz + name_len + mod_len)
			new_cap = ksyms->strs_sz + name_len + mod_len;
		if (new_cap < 1024)
			new_cap = 1024;
		tmp = realloc(ksyms->strs, new_cap);
		if (!tmp)
			return -1;
		ksyms->strs = tmp;
		ksyms->strs_cap = new_cap;
	}
	if (ksyms->syms_sz + 1 > ksyms->syms_cap) {
		new_cap = ksyms->syms_cap * 4 / 3;
		if (new_cap < 1024)
			new_cap = 1024;
		tmp = realloc(ksyms->syms, sizeof(*ksyms->syms) * new_cap);
		if (!tmp)
			return -1;
		ksyms->syms = tmp;
		ksyms->syms_cap = new_cap;
	}

	ksym = &ksyms->syms[ksyms->syms_sz];
	/* while constructing, re-use pointer as just a plain offset */
	ksym->name = (void *)(unsigned long)ksyms->strs_sz;
	if (mod)
		ksym->module = (void *)(unsigned long)(ksyms->strs_sz + name_len);
	else
		ksym->module = NULL;
	ksym->addr = addr;
	/* mark which symbols are functions for post-processing */
	ksym->size = (sym_type == 't' || sym_type == 'T') ? (unsigned long)-1 : 0;
	ksym->kind = (sym_type == 't' || sym_type == 'T') ? KSYM_FUNC : KSYM_DATA;

	memcpy(ksyms->strs + ksyms->strs_sz, name, name_len);
	ksyms->strs_sz += name_len;
	if (mod_len) {
		memcpy(ksyms->strs + ksyms->strs_sz, mod, mod_len);
		ksyms->strs_sz += mod_len;
	}

	ksyms->syms_sz++;

	return 0;
}

static int ksym_cmp(const void *p1, const void *p2)
{
	const struct ksym *s1 = p1, *s2 = p2;

	if (s1->addr == s2->addr)
		return strcmp(s1->name, s2->name);
	return s1->addr < s2->addr ? -1 : 1;
}

static int ksym_by_kind_name_cmp(const void *p1, const void *p2)
{
	const struct ksym * const *sp1 = p1, * const *sp2 = p2;
	const struct ksym *s1 = *sp1, *s2 = *sp2;

	if (s1->kind != s2->kind)
		return s1->kind < s2->kind ? -1 : 1;
	return strcmp(s1->name, s2->name);
}

struct ksyms *ksyms__load(void)
{
	char sym_type, sym_name[256], mod_buf[128], *mod_name;
	struct ksyms *ksyms;
	unsigned long sym_addr;
	int i, ret;
	FILE *f;

	f = fopen("/proc/kallsyms", "r");
	if (!f)
		return NULL;

	ksyms = calloc(1, sizeof(*ksyms));
	if (!ksyms)
		goto err_out;

	while (true) {
		ret = fscanf(f, "%lx %c %s%[^\n]\n",
			     &sym_addr, &sym_type, sym_name, mod_buf);
		if (ret == EOF && feof(f))
			break;
		if (ret != 3 && ret != 4)
			goto err_out;
		mod_name = NULL;
		if (ret == 4) {
			/* mod_buf will be '    [module]', so we need to
			 * extract module name from it
			 */
			mod_name = mod_buf;
			while (*mod_name && (isspace(*mod_name) || *mod_name == '['))
				mod_name++;
			mod_name[strlen(mod_name) - 1] = '\0';
		}
		if (ksyms__add_symbol(ksyms, sym_name, mod_name, sym_addr, sym_type))
			goto err_out;
	}
	fclose(f);

	ksyms->syms_by_kind_name = calloc(ksyms->syms_sz, sizeof(*ksyms->syms_by_kind_name));
	if (!ksyms->syms_by_kind_name)
		goto err_out;

	/* now when strings are finalized, adjust pointers properly */
	for (i = 0; i < ksyms->syms_sz; i++) {
		ksyms->syms[i].name += (unsigned long)ksyms->strs;
		if (ksyms->syms[i].module)
			ksyms->syms[i].module += (unsigned long)ksyms->strs;
		ksyms->syms_by_kind_name[i] = &ksyms->syms[i];
	}

	qsort(ksyms->syms, ksyms->syms_sz, sizeof(*ksyms->syms), ksym_cmp);
	qsort(ksyms->syms_by_kind_name, ksyms->syms_sz,
	      sizeof(*ksyms->syms_by_kind_name), ksym_by_kind_name_cmp);

	/* do another pass to calculate (guess?) function sizes */
	for (i = 0; i < ksyms->syms_sz; i++) {
		struct ksym *ksym = &ksyms->syms[i];
		struct ksym *next_ksym = ksym + 1;

		if (!ksym->size)
			continue;

		if (i + 1 < ksyms->syms_sz && next_ksym->size)
			ksym->size = next_ksym->addr - ksym->addr;
		else
			ksym->size = 0;
	}

	return ksyms;

err_out:
	ksyms__free(ksyms);
	fclose(f);
	return NULL;
}

void ksyms__free(struct ksyms *ksyms)
{
	if (!ksyms)
		return;

	free(ksyms->syms);
	free(ksyms->strs);
	free(ksyms);
}

const struct ksym *ksyms__map_addr(const struct ksyms *ksyms,
				   unsigned long addr)
{
	int start = 0, end = ksyms->syms_sz - 1, mid;
	unsigned long sym_addr;

	/* find largest sym_addr <= addr using binary search */
	while (start < end) {
		mid = start + (end - start + 1) / 2;
		sym_addr = ksyms->syms[mid].addr;

		if (sym_addr <= addr)
			start = mid;
		else
			end = mid - 1;
	}

	if (start == end && ksyms->syms[start].addr <= addr)
		return &ksyms->syms[start];
	return NULL;
}

const struct ksym *ksyms__get_symbol(const struct ksyms *ksyms,
				     const char *name, enum ksym_kind kind)
{
	struct ksym ksym = { .kind = kind, .name = name };
	struct ksym *key = &ksym;
	const struct ksym **res;

	res = bsearch(&key, ksyms->syms_by_kind_name,
		      ksyms->syms_sz, sizeof(*ksyms->syms_by_kind_name),
		      ksym_by_kind_name_cmp);
	if (res)
		return *res;

	return NULL;
}
