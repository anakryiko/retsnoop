/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef __KSYMS_H
#define __KSYMS_H

struct ksym {
	const char *name;
	unsigned long addr;
	unsigned long size;
};

struct ksyms;

struct ksyms *ksyms__load(void);
void ksyms__free(struct ksyms *ksyms);
const struct ksym *ksyms__map_addr(const struct ksyms *ksyms,
				   unsigned long addr);
const struct ksym *ksyms__get_symbol(const struct ksyms *ksyms,
				     const char *name);

#endif /* __KSYMS_H */
