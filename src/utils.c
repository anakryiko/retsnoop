// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include "utils.h"
#include "mass_attacher.h"

static const char *err_map[] = {
	[0] = "NULL",
	[1] = "EPERM", [2] = "ENOENT", [3] = "ESRCH",
	[4] = "EINTR", [5] = "EIO", [6] = "ENXIO", [7] = "E2BIG",
	[8] = "ENOEXEC", [9] = "EBADF", [10] = "ECHILD", [11] = "EAGAIN",
	[12] = "ENOMEM", [13] = "EACCES", [14] = "EFAULT", [15] = "ENOTBLK",
	[16] = "EBUSY", [17] = "EEXIST", [18] = "EXDEV", [19] = "ENODEV",
	[20] = "ENOTDIR", [21] = "EISDIR", [22] = "EINVAL", [23] = "ENFILE",
	[24] = "EMFILE", [25] = "ENOTTY", [26] = "ETXTBSY", [27] = "EFBIG",
	[28] = "ENOSPC", [29] = "ESPIPE", [30] = "EROFS", [31] = "EMLINK",
	[32] = "EPIPE", [33] = "EDOM", [34] = "ERANGE", [35] = "EDEADLK",
	[36] = "ENAMETOOLONG", [37] = "ENOLCK", [38] = "ENOSYS", [39] = "ENOTEMPTY",
	[40] = "ELOOP", [42] = "ENOMSG", [43] = "EIDRM", [44] = "ECHRNG",
	[45] = "EL2NSYNC", [46] = "EL3HLT", [47] = "EL3RST", [48] = "ELNRNG",
	[49] = "EUNATCH", [50] = "ENOCSI", [51] = "EL2HLT", [52] = "EBADE",
	[53] = "EBADR", [54] = "EXFULL", [55] = "ENOANO", [56] = "EBADRQC",
	[57] = "EBADSLT", [59] = "EBFONT", [60] = "ENOSTR", [61] = "ENODATA",
	[62] = "ETIME", [63] = "ENOSR", [64] = "ENONET", [65] = "ENOPKG",
	[66] = "EREMOTE", [67] = "ENOLINK", [68] = "EADV", [69] = "ESRMNT",
	[70] = "ECOMM", [71] = "EPROTO", [72] = "EMULTIHOP", [73] = "EDOTDOT",
	[74] = "EBADMSG", [75] = "EOVERFLOW", [76] = "ENOTUNIQ", [77] = "EBADFD",
	[78] = "EREMCHG", [79] = "ELIBACC", [80] = "ELIBBAD", [81] = "ELIBSCN",
	[82] = "ELIBMAX", [83] = "ELIBEXEC", [84] = "EILSEQ", [85] = "ERESTART",
	[86] = "ESTRPIPE", [87] = "EUSERS", [88] = "ENOTSOCK", [89] = "EDESTADDRREQ",
	[90] = "EMSGSIZE", [91] = "EPROTOTYPE", [92] = "ENOPROTOOPT", [93] = "EPROTONOSUPPORT",
	[94] = "ESOCKTNOSUPPORT", [95] = "EOPNOTSUPP", [96] = "EPFNOSUPPORT", [97] = "EAFNOSUPPORT",
	[98] = "EADDRINUSE", [99] = "EADDRNOTAVAIL", [100] = "ENETDOWN", [101] = "ENETUNREACH",
	[102] = "ENETRESET", [103] = "ECONNABORTED", [104] = "ECONNRESET", [105] = "ENOBUFS",
	[106] = "EISCONN", [107] = "ENOTCONN", [108] = "ESHUTDOWN", [109] = "ETOOMANYREFS",
	[110] = "ETIMEDOUT", [111] = "ECONNREFUSED", [112] = "EHOSTDOWN", [113] = "EHOSTUNREACH",
	[114] = "EALREADY", [115] = "EINPROGRESS", [116] = "ESTALE", [117] = "EUCLEAN",
	[118] = "ENOTNAM", [119] = "ENAVAIL", [120] = "EISNAM", [121] = "EREMOTEIO",
	[122] = "EDQUOT", [123] = "ENOMEDIUM", [124] = "EMEDIUMTYPE", [125] = "ECANCELED",
	[126] = "ENOKEY", [127] = "EKEYEXPIRED", [128] = "EKEYREVOKED", [129] = "EKEYREJECTED",
	[130] = "EOWNERDEAD", [131] = "ENOTRECOVERABLE", [132] = "ERFKILL", [133] = "EHWPOISON",
	[512] = "ERESTARTSYS", [513] = "ERESTARTNOINTR", [514] = "ERESTARTNOHAND", [515] = "ENOIOCTLCMD",
	[516] = "ERESTART_RESTARTBLOCK", [517] = "EPROBE_DEFER", [518] = "EOPENSTALE", [519] = "ENOPARAM",
	[521] = "EBADHANDLE", [522] = "ENOTSYNC", [523] = "EBADCOOKIE", [524] = "ENOTSUPP",
	[525] = "ETOOSMALL", [526] = "ESERVERFAULT", [527] = "EBADTYPE", [528] = "EJUKEBOX",
	[529] = "EIOCBQUEUED", [530] = "ERECALLCONFLICT",
};

int str_to_err(const char *arg)
{
	int i;

	/* doesn't matter if it's -Exxx or Exxx */
	if (arg[0] == '-')
		arg++;

	for (i = 0; i < ARRAY_SIZE(err_map); i++) {
		if (!err_map[i])
			continue;

		if (strcmp(arg, err_map[i]) != 0)
			continue;

		return i;
	}

	fprintf(stderr, "Unrecognized error '%s'\n", arg);
	return -ENOENT;
}

const char *err_to_str(long err)
{

	if (err < 0)
		err = -err;
	if (err < ARRAY_SIZE(err_map))
		return err_map[err];
	return NULL;
}


void ts_to_str(uint64_t ts, char buf[], size_t buf_sz)
{
	char tmp[32];
	time_t t = ts / 1000000000;
	struct tm tm;

	localtime_r(&t, &tm);
	strftime(tmp, sizeof(tmp), "%H:%M:%S", &tm);

	snprintf(buf, buf_sz, "%s.%06lu", tmp, ts / 1000 % 1000000);
}

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

int append_glob(struct glob **globs, int *cnt, const char *str, bool mandatory)
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
		g->mandatory = mandatory;
		if (!g->name || !g->mod) {
			free(g->name);
			free(g->mod);
			return -ENOMEM;
		}
	} else {
		g->name = strdup(str);
		g->mod = NULL;
		g->mandatory = mandatory;
		if (!g->name)
			return -ENOMEM;
	}

	*cnt = *cnt + 1;
	return 0;
}

int append_glob_file(struct glob **globs, int *cnt, const char *file, bool mandatory)
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
		if (append_glob(globs, cnt, buf, mandatory)) {
			err = -ENOMEM;
			goto cleanup;
		}
	}

cleanup:
	fclose(f);
	return err;
}

int append_compile_unit(struct addr2line *a2l, struct glob **globs, int *cnt,
			const char *cu, bool mandatory)
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
		if (append_glob(globs, cnt, cu_resps[i].fname, mandatory)) {
			err = -ENOMEM;
			break;
		}
	}

	free(cu_resps);
	return err;
}

int append_pid(int **pids, int *cnt, const char *arg)
{
	void *tmp;
	int pid;

	errno = 0;
	pid = strtol(arg, NULL, 10);
	if (errno || pid < 0) {
		fprintf(stderr, "Invalid PID: %d\n", pid);
		return -EINVAL;
	}

	tmp = realloc(*pids, (*cnt + 1) * sizeof(**pids));
	if (!tmp)
		return -ENOMEM;
	*pids = tmp;

	(*pids)[*cnt] = pid;
	*cnt = *cnt + 1;

	return 0;
}

static bool is_valid_glob(const char *glob)
{
	int n;

	if (!glob) {
		fprintf(stderr, "NULL glob provided.\n");
		return false;
	}

	n = strlen(glob);
	if (n == 0) {
		fprintf(stderr, "Empty glob provided.\n");
		return false;
	}

	if (strcmp(glob, "**") == 0) {
		fprintf(stderr, "Unsupported glob '%s'.\n", glob);
		return false;
	}

	return true;
}

int glob_set__add_glob(struct glob_set *gs, const char *glob, const char *mod_glob, enum glob_flags flags)
{
	void *tmp, *s1, *s2 = NULL;
	struct glob_spec *g;

	/* exactly one of GLOB_ALLOW or GLOB_DENY should be set */
	if (!(flags & (GLOB_ALLOW | GLOB_DENY)))
		return -EINVAL;
	if ((flags & (GLOB_ALLOW | GLOB_DENY)) == (GLOB_ALLOW | GLOB_DENY))
		return -EINVAL;
	if (!is_valid_glob(glob))
		return -EINVAL;
	if (mod_glob && !is_valid_glob(mod_glob))
		return -EINVAL;

	tmp = realloc(gs->globs, (gs->glob_cnt + 1) * sizeof(*gs->globs));
	if (!tmp)
		return -ENOMEM;
	gs->globs = tmp;

	g = &gs->globs[gs->glob_cnt];
	memset(g, 0, sizeof(*g));

	s1 = strdup(glob);
	if (!s1)
		return -ENOMEM;
	if (mod_glob) {
		s2 = strdup(mod_glob);
		if (!s2) {
			free(s1);
			return -ENOMEM;
		}
	}

	g->glob = s1;
	g->mod_glob = s2;
	g->flags = flags;

	gs->glob_cnt += 1;

	return 0;
}

/* Find matching glob and return its index. GLOB_DENY globs are checked and
 * matched first. If no GLOB_DENY matches, then GLOB_ALLOW globs are checked.
 * Return true, if glob set allows given name/mod pair. If there was explicit
 * GLOB_ALLOW glob that matched, its index is returned in glob_idx, otherwise
 * glob_idx is set to -ENOENT;
 * Return false, if glob set disallows given name/mod pair. If there was
 * explicit GLOB_DENY glob that matched, its index is returned in glob_idx,
 * otherwise glob_idx is set to -ENOENT.
 * glob_idx pointer is optional and can be NULL.
 */
bool glob_set__match(const struct glob_set *gs, const char *name, const char *mod, int *glob_idx)
{
	struct glob_spec *g;
	int i, deny_glob_cnt = 0;

	if (glob_idx)
		*glob_idx = -ENOENT;

	for (i = 0; i < gs->glob_cnt; i++) {
		g = &gs->globs[i];
		if (!(g->flags & GLOB_DENY))
			continue;

		deny_glob_cnt++;

		if (full_glob_matches(g->glob, g->mod_glob, name, mod)) {
			if (glob_idx)
				*glob_idx = i;
			return false; /* explicit mismatch */
		}
	}

	/* if no explicit GLOB_ALLOW globs are specified, we are OK */
	if (deny_glob_cnt == gs->glob_cnt)
		return true; /* implicit match */

	/* if any allow glob is specified, function has to match one of them */
	for (i = 0; i < gs->glob_cnt; i++) {
		g = &gs->globs[i];
		if (!(g->flags & GLOB_ALLOW))
			continue;

		if (full_glob_matches(g->glob, g->mod_glob, name, mod)) {
			if (glob_idx)
				*glob_idx = i;
			return true; /* explicit match */
		}
	}

	return false; /* implicit mismatch */
}

void glob_set__clear(struct glob_set *gs)
{
	int i;

	for (i = 0; i < gs->glob_cnt; i++) {
		free(gs->globs[i].glob);
		free(gs->globs[i].mod_glob);
	}
	free(gs->globs);
	gs->globs = NULL;
	gs->glob_cnt = 0;
}

uint64_t ktime_off;

void calibrate_ktime(void)
{
	int i;
	struct timespec t1, t2, t3;
	uint64_t best_delta = 0, delta, ts;

	for (i = 0; i < 10; i++) {
		clock_gettime(CLOCK_REALTIME, &t1);
		clock_gettime(CLOCK_MONOTONIC, &t2);
		clock_gettime(CLOCK_REALTIME, &t3);

		delta = timespec_to_ns(&t3) - timespec_to_ns(&t1);
		ts = (timespec_to_ns(&t3) + timespec_to_ns(&t1)) / 2;

		if (i == 0 || delta < best_delta) {
			best_delta = delta;
			ktime_off = ts - timespec_to_ns(&t2);
		}
	}
}

int snprintf_smart_uint(char *buf, size_t buf_sz, unsigned long long value)
{
	if ((unsigned long)value < 4 * 1024 * 1024)
		return snprintf(buf, buf_sz, "%llu", value);
	else
		return snprintf(buf, buf_sz, "0x%llx", value);
}

int snprintf_smart_int(char *buf, size_t buf_sz, long long value)
{
	if (value < 4 * 1024 * 1024 /* random heuristic */)
		return snprintf(buf, buf_sz, "%lld", value);
	else
		return snprintf(buf, buf_sz, "0x%llx", value);
}

void snprintf_inj_probe(char *buf, size_t buf_sz, const struct inj_probe_info *inj)
{
	switch (inj->type) {
	case INJ_KPROBE:
		snprintf(buf, buf_sz, "kprobe:%s+0x%lx", inj->kprobe.name, inj->kprobe.offset);
		break;
	case INJ_KRETPROBE:
		snprintf(buf, buf_sz, "kretprobe:%s", inj->kprobe.name);
		break;
	case INJ_RAWTP:
		snprintf(buf, buf_sz, "rawtp:%s", inj->rawtp.name);
		break;
	case INJ_TP:
		snprintf(buf, buf_sz, "tp:%s:%s", inj->tp.category, inj->tp.name);
		break;
	}
}

