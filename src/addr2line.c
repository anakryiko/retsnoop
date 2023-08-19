// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2021 Facebook */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <libelf.h>
#include <gelf.h>

#include "addr2line.h"
 
extern char __binary_sidecar_start[];
extern char __binary_sidecar_end[];

struct addr2line {
	FILE *read_pipe;
	FILE *write_pipe;
	bool inlines;
	bool verbose;
	long kaslr_offset;
};

long addr2line__kaslr_offset(const struct addr2line *a2l)
{
	return a2l->kaslr_offset;
}

void addr2line__free(struct addr2line *a2l)
{
	if (!a2l)
		return;

	if (a2l->read_pipe)
		fclose(a2l->read_pipe);
	if (a2l->write_pipe)
		fclose(a2l->write_pipe);

	free(a2l);
}

static void sig_pipe(int signo)
{
	printf("SIGPIPE caught, exiting!\n");
	exit(1);
}

static void child_driver(int fd1[2], int fd2[2], const char *vmlinux, bool inlines, char **envp)
{
	size_t a2l_sz = __binary_sidecar_end - __binary_sidecar_start;
	char *argv[] = {
		"addr2line", "-f", "--llvm", "-e", (char *)vmlinux,
		inlines ? "-i" : NULL, NULL,
	};
	int a2l_rwfd, a2l_rofd, ppid;
	FILE *a2l_bin;
	char buf[256];
	size_t ret;

	close(fd1[1]);
	close(fd2[0]);

	if (fd1[0] != STDIN_FILENO) {
		if (dup2(fd1[0], STDIN_FILENO) != STDIN_FILENO) {
			fprintf(stderr, "CHILD: failed to dup2() stdin: %d\n", -errno);
			goto kill_parent;
		}
		close(fd1[0]);
	}
	if (fd2[1] != STDOUT_FILENO) {
		if (dup2(fd2[1], STDOUT_FILENO) != STDOUT_FILENO) {
			fprintf(stderr, "CHILD: failed to dup2() stdout: %d\n", -errno);
			goto kill_parent;
		}
		close(fd2[1]);
	}

	/* We have addr2line embedded inside retsnoop. Now create
	 * temporary file (which will be unlinked inside tmpfile()
	 * itself, so will be cleaned up once last fd is closed), dump
	 * addr2line binary contents into it, flush, re-open as
	 * read-only file, close the R/W FD to avoid -ETXTBUSY, make
	 * R/O FD executable and use fexecve() to exec from that
	 * ephemeral file.
	 */
	a2l_bin = tmpfile();
	if (!a2l_bin) {
		fprintf(stderr, "CHILD: failed to create temp file: %d\n", -errno);
		goto kill_parent;
	}

	ret = fwrite(__binary_sidecar_start, 1, a2l_sz, a2l_bin);
	if (ret != a2l_sz) {
		fprintf(stderr, "CHILD: failed to write addr2line contents: %d\n", -errno);
		goto kill_parent;
	}

	fflush(a2l_bin);
	fseek(a2l_bin, 0L, SEEK_SET);
	a2l_rwfd = fileno(a2l_bin);

	snprintf(buf, sizeof(buf), "/proc/self/fd/%d", a2l_rwfd);
	a2l_rofd = open(buf, O_RDONLY | O_CLOEXEC);
	if (a2l_rofd < 0) {
		fprintf(stderr, "CHILD: failed to re-open() addr2line as R/O: %d\n", -errno);
		goto kill_parent;
	}

	fclose(a2l_bin);

	if (fchmod(a2l_rofd, S_IXUSR | S_IWUSR | S_IRUSR) < 0) {
		fprintf(stderr, "CHILD: failed to fchmod() addr2line: %d\n", -errno);
		goto kill_parent;
	}

	if (fexecve(a2l_rofd, argv, envp) < 0) {
		fprintf(stderr, "CHILD: failed to fexecve() addr2line: %d\n", -errno);
		goto kill_parent;
	}

kill_parent:
	ppid = getppid();
	fprintf(stderr, "CHILD: killing parent (PID %d)...\n", ppid);
	kill(ppid, SIGTERM);
	exit(1);
}

/* Find the start of .text section (which should correspond to _stext ksym)
 * in provided vmlinux ELF binary. This will be used to calculate correct
 * KASLR offset.
 */
static int find_stext_elf_addr(const char *vmlinux, long *addr)
{
	size_t shstr_sec_idx, sec_cnt;
	Elf_Scn *scn;
	Elf *elf;
	int fd, err;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "Failed to initialize libelf: %s\n", elf_errmsg(-1));
		return -EINVAL;
	}

	fd = open(vmlinux, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Failed to open '%s': %d\n", vmlinux, -errno);
		return -EIO;
	}

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!elf) {
		fprintf(stderr, "Failed to open '%s' as ELF file: %s\n", vmlinux, elf_errmsg(-1));
		err = -EIO;
		goto cleanup;
	}

	if (elf_getshdrstrndx(elf, &shstr_sec_idx) || elf_getshdrnum(elf, &sec_cnt)) {
		fprintf(stderr, "Failed to query '%s' as ELF file: %s\n", vmlinux, elf_errmsg(-1));
		err = -EIO;
		goto cleanup;
	}

	scn = NULL;
	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		GElf_Shdr shdr;
		const char *sec_name;

		if (!gelf_getshdr(scn, &shdr)) {
			fprintf(stderr, "Failed to fetch section header #%zu from '%s': %s\n",
				elf_ndxscn(scn), vmlinux, elf_errmsg(-1));
			err = -EIO;
			goto cleanup;
		}

		/* Looking for .text section is faster than looking for _stext
		 * symbol in symbol table. They are supposed to be pointing to
		 * the same base load address. So we cut corner here.
		 */
		sec_name = elf_strptr(elf, shstr_sec_idx, shdr.sh_name);
		if (sec_name && strcmp(sec_name, ".text") == 0) {
			*addr = shdr.sh_addr;
			err = 0; /* success */
			goto cleanup;
		}
	}

	err = -ESRCH;
cleanup:
	if (elf)
		elf_end(elf);
	close(fd);
	return err;
}

/* stext_addr is real address of `_stext` symbol, which represents the start
 * of kernel .text section. This is used to calculate KASLR offset to
 * compensate for during matching real (potentially randomized) kernel
 * addresses against non-randomized addresses recorded in ELF and DWARF data.
 */
struct addr2line *addr2line__init(const char *vmlinux, long stext_addr, bool verbose, bool inlines, char **envp)
{
	struct addr2line *a2l;
	int fd1[2], fd2[2], pid;
	long stext_elf_addr = 0;

	a2l = calloc(1, sizeof(*a2l));
	if (!a2l)
		return NULL;

	a2l->verbose = verbose;

	if (find_stext_elf_addr(vmlinux, &stext_elf_addr)) {
		fprintf(stderr, "Failed to determine kernel image address (KASLR) from '%s'! Zero is assumed.\n",
			vmlinux);
		a2l->kaslr_offset = 0;
	} else {
		a2l->kaslr_offset = stext_addr - stext_elf_addr;
		if (a2l->verbose)
			printf("KASLR offset is 0x%lx.\n", a2l->kaslr_offset);
	}

	if (signal(SIGPIPE, sig_pipe) == SIG_ERR) {
		fprintf(stderr, "Failed to install SIGPIPE handler: %d\n", -errno);
		goto err_out;
	}

	if (pipe(fd1) < 0 || pipe(fd2) < 0) {
		fprintf(stderr, "Failed to create pipes for addr2line: %d\n", -errno);
		goto err_out;
	}

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "Failed to fork() addr2line: %d\n", -errno);
		goto err_out;
	}

	/* CHILD PROCESS */
	if (pid == 0) {
		child_driver(fd1, fd2, vmlinux, inlines, envp);
		exit(2); /* should never reach this */
	}

	if (a2l->verbose)
		printf("Sidecar PID is %d.\n", pid);

	close(fd1[0]);
	close(fd2[1]);

	a2l->write_pipe = fdopen(fd1[1], "w");
	if (!a2l->write_pipe) {
		fprintf(stderr, "Failed to fdopen() write pipe: %d\n", -errno);
		goto err_out;
	}
	a2l->read_pipe = fdopen(fd2[0], "r");
	if (!a2l->read_pipe) {
		fprintf(stderr, "Failed to fdopen() write pipe: %d\n", -errno);
		goto err_out;
	}

	return a2l;

err_out:
	addr2line__free(a2l);
	return NULL;
}

int addr2line__symbolize(const struct addr2line *a2l, long addr, struct a2l_resp *resp)
{
	int err, cnt = 0;

	err = fprintf(a2l->write_pipe, "symbolize %lx\n", addr - a2l->kaslr_offset);
	if (err <= 0) {
		err = -errno;
		fprintf(stderr, "Failed to symbolize %lx (%lx): %d\n",
			addr, addr - a2l->kaslr_offset, err);
		return err;
	}
	fflush(a2l->write_pipe);

	while (true) {
		if (fgets(resp->fname, sizeof(resp->fname), a2l->read_pipe) == NULL) {
			err = -errno;
			fprintf(stderr, "Failed to get symbolized function name: %d\n", err);
			return err;
		}
		resp->fname[strlen(resp->fname) - 1] = '\0';

		/* empty line denotes end of response */
		if (resp->fname[0] == '\0')
			break;

		if (fgets(resp->line, sizeof(resp->line), a2l->read_pipe) == NULL) {
			err = -errno;
			fprintf(stderr, "Failed to get file/line info: %d\n", err);
			return err;
		}

		resp->line[strlen(resp->line) - 1] = '\0';

		if (strcmp(resp->line, "??:0:0") == 0)
			continue;

		resp++;
		cnt++;
	}

	return cnt;
}

int addr2line__query_symbols(const struct addr2line *a2l, const char *compile_unit,
			     struct a2l_cu_resp **resp_ret)
{
	int cnt = 0;
	int buf_size = 64;
	int err = 0;
	struct a2l_cu_resp *buf = NULL;
	struct a2l_cu_resp *resp;

	err = fprintf(a2l->write_pipe, "query_syms %s\n", compile_unit);
	if (err <= 0) {
		err = -errno;
		fprintf(stderr, "Failed to get function names from compile unit(s): %d\n", err);
		return err;
	}
	fflush(a2l->write_pipe);

	buf = (struct a2l_cu_resp *)malloc(sizeof(struct a2l_cu_resp) * buf_size);
	if (buf == NULL) {
		return -ENOMEM;
	}

	err = 0;
	while (true) {
		char line[256];
		if (fgets(line, sizeof(line), a2l->read_pipe) == NULL) {
			err = -errno;
			fprintf(stderr, "Failed to get functions from compile unit(s): %d\n", err);
			break;
		}
		if (line[0] == ':') {
			if (line[1] == 'q') {
				/* :q is the last end of the result */
				break;
			}
			/* Skip :e lines since we don't need filename so far */
			continue;
		}
		if (line[0] != ' ') {
			fprintf(stderr, "Invalid format: %s\n", line);
			err = -1;
			break;
		}
		/* |line| should be in the format of <spc><fuction><spc><address> */

		if (cnt >= buf_size) {
			buf_size *= 2;
			buf = (struct a2l_cu_resp *)realloc(buf, sizeof(struct a2l_cu_resp) * buf_size);
			if (buf == NULL) {
				err = -ENOMEM;
				break;
			}
		}
		resp = buf + cnt;

		/* Get function name */
		char *sep = strchr(line + 1, ' ');
		if (sep == NULL) {
			fprintf(stderr, "Invalid format: %s\n", line);
			err = -1;
			break;
		}
		*sep = 0;

		if (sep - (line + 1) >= sizeof(resp->fname)) {
			fprintf(stderr, "Function name is too long: %s\n", line + 1);
			err = -1;
			break;
		}
		strcpy(resp->fname, line + 1);

		/* Get address */
		char *addr_str = sep + 1;
		if (addr_str[0] != '0' || addr_str[1] != 'x') {
			fprintf(stderr, "Invalid address for function: %s %s\n", resp->fname, addr_str);
			err = -1;
			break;
		}
		addr_str += 2;
		resp->address = (void *)(uintptr_t)strtoul(addr_str, NULL, 16);
		/* compensate for KASLR */
		resp->address += a2l->kaslr_offset;

		cnt++;
	}

	if (err) {
		if (buf != NULL)
			free(buf);
		return err;
	}

	*resp_ret = buf;
	return cnt;
}

