/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2021 Facebook */
#ifndef __ADDR2LINE_H
#define __ADDR2LINE_H

struct a2l_resp
{
	char fname[128];
	char line[512];
};

struct a2l_cu_resp
{
	char fname[128 - sizeof(void*)]; /* Reduce fragment */
	void* address;
};

struct addr2line;

struct addr2line *addr2line__init(const char *vmlinux, long stext_addr, bool verbose, bool inlines, char **envp);
void addr2line__free(struct addr2line *a2l);

long addr2line__kaslr_offset(const struct addr2line *a2l);
int addr2line__symbolize(const struct addr2line *a2l, long addr, struct a2l_resp *resp);
int addr2line__query_symbols(const struct addr2line *a2l, const char *compile_unit, struct a2l_cu_resp **resp_ret);

#endif /* __ADDR2LINE_H */
