/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef __KSYMS_H
#define __KSYMS_H

enum ksym_kind {
	KSYM_FUNC,
	KSYM_DATA,
};

struct ksym {
	const char *name;
	const char *module;
	unsigned long addr;
	unsigned long size;
	enum ksym_kind kind;
};

struct ksyms;

struct ksyms *ksyms__load(void);
void ksyms__free(struct ksyms *ksyms);
const struct ksym *ksyms__map_addr(const struct ksyms *ksyms,
				   unsigned long addr);
const struct ksym *ksyms__get_symbol(const struct ksyms *ksyms,
				     const char *module, const char *name,
				     enum ksym_kind kind);

#endif /* __KSYMS_H */
