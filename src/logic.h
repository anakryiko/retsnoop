/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2024 Meta Platforms, Inc. */
#ifndef __LOGIC_H
#define __LOGIC_H

#include <stdint.h>
#include "utils.h"
#include "env.h"

const struct func_info *func_info(const struct ctx *ctx, __u32 id);

enum func_flags;

int func_flags(const char *func_name, const struct btf *btf, int btf_id);
void format_func_flags(char *buf, size_t buf_sz, enum func_flags flags);

int init_func_traces(void);

int handle_event(void *ctx, void *data, size_t data_sz);

long read_dropped_sessions(void);

#endif /* __LOGIC_H */
