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

#include "addr2line.h"
 
extern char _binary____tools_addr2line_start[];
extern char _binary____tools_addr2line_end[];

struct addr2line {
	FILE *read_pipe;
	FILE *write_pipe;
	bool inlines;
};

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

static void child_driver(int fd1[2], int fd2[2], const char *vmlinux, bool inlines)
{
	size_t a2l_sz = _binary____tools_addr2line_end - _binary____tools_addr2line_start;
	char *argv[] = {
		"addr2line", "-f", "--llvm", "-e", (char *)vmlinux,
		inlines ? "-i" : NULL, NULL,
	};
	char *envp[] = { NULL };
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

	ret = fwrite(_binary____tools_addr2line_start, 1, a2l_sz, a2l_bin);
	if (ret != a2l_sz) {
		fprintf(stderr, "CHILD: failed to write addr2line contents: %d\n", -errno);
		goto kill_parent;
	}

	fflush(a2l_bin);
	fseek(a2l_bin, 0L, SEEK_SET);
	a2l_rwfd = fileno(a2l_bin);

	snprintf(buf, sizeof(buf), "/proc/self/fd/%d", a2l_rwfd);
	a2l_rofd = open(buf, O_RDONLY, O_CLOEXEC);
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

struct addr2line *addr2line__init(const char *vmlinux, bool inlines)
{
	struct addr2line *a2l;
	int fd1[2], fd2[2];
	int pid;

	a2l = calloc(1, sizeof(*a2l));
	if (!a2l)
		return NULL;

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
		child_driver(fd1, fd2, vmlinux, inlines);
		exit(2); /* should never reach this */
	}

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

	err = fprintf(a2l->write_pipe, "%lx\n", addr);
	if (err <= 0) {
		err = -errno;
		fprintf(stderr, "Failed to symbolize %lx: %d\n", addr, err);
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

