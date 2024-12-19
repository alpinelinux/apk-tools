/* pid.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2024 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>

#include "apk_io.h"
#include "apk_process.h"
#include "apk_print.h"

static void close_fd(int *fd)
{
	if (*fd <= 0) return;
	close(*fd);
	*fd = -1;
}

static void set_non_blocking(int fd)
{
	if (fd >= 0) fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}

int apk_process_init(struct apk_process *p, const char *argv0, struct apk_out *out, struct apk_istream *is)
{
	*p = (struct apk_process) {
		.argv0 = argv0,
		.is = is,
		.out = out,
	};
	if (IS_ERR(is)) return -PTR_ERR(is);

	if (is) pipe2(p->pipe_stdin, O_CLOEXEC);
	else {
		p->pipe_stdin[0] = open("/dev/null", O_RDONLY);
		p->pipe_stdin[1] = -1;
	}

	pipe2(p->pipe_stdout, O_CLOEXEC);
	pipe2(p->pipe_stderr, O_CLOEXEC);

	set_non_blocking(p->pipe_stdin[1]);
	set_non_blocking(p->pipe_stdout[0]);
	set_non_blocking(p->pipe_stderr[0]);

	return 0;
}

static int buf_process(struct buf *b, int fd, struct apk_out *out, const char *prefix, const char *argv0)
{
	ssize_t n = read(fd, &b->buf[b->len], sizeof b->buf - b->len);
	if (n <= 0) {
		if (b->len) {
			apk_out_fmt(out, prefix, "%s: %.*s", argv0, (int)b->len, b->buf);
			b->len = 0;
		}
		return 0;
	}

	b->len += n;

	uint8_t *pos, *lf, *end = &b->buf[b->len];
	for (pos = b->buf; (lf = memchr(pos, '\n', end - pos)) != NULL; pos = lf + 1) {
		apk_out_fmt(out, prefix, "%s: %.*s", argv0, (int)(lf - pos), pos);
	}

	b->len = end - pos;
	memmove(b->buf, pos, b->len);
	return 1;
}

pid_t apk_process_fork(struct apk_process *p)
{
	pid_t pid = fork();
	if (pid < 0) return pid;
	if (pid == 0) {
		dup2(p->pipe_stdin[0], STDIN_FILENO);
		dup2(p->pipe_stdout[1], STDOUT_FILENO);
		dup2(p->pipe_stderr[1], STDERR_FILENO);
		close_fd(&p->pipe_stdin[1]);
		close_fd(&p->pipe_stdout[0]);
		close_fd(&p->pipe_stderr[0]);
		return pid;
	} else {
		p->pid = pid;
	}
	close_fd(&p->pipe_stdin[0]);
	close_fd(&p->pipe_stdout[1]);
	close_fd(&p->pipe_stderr[1]);
	return pid;
}

int apk_process_run(struct apk_process *p)
{
	struct pollfd fds[3] = {
		{ .fd = p->pipe_stdout[0], .events = POLLIN },
		{ .fd = p->pipe_stderr[0], .events = POLLIN },
		{ .fd = p->pipe_stdin[1],  .events = POLLOUT },
	};

	while (fds[0].fd >= 0 || fds[1].fd >= 0 || fds[2].fd >= 0) {
		if (poll(fds, ARRAY_SIZE(fds), -1) <= 0) continue;
		if (fds[0].revents) {
			if (!buf_process(&p->buf_stdout, p->pipe_stdout[0], p->out, NULL, p->argv0)) {
				fds[0].fd = -1;
				close_fd(&p->pipe_stdout[0]);
			}
		}
		if (fds[1].revents) {
			if (!buf_process(&p->buf_stderr, p->pipe_stderr[0], p->out, "", p->argv0)) {
				fds[1].fd = -1;
				close_fd(&p->pipe_stderr[0]);
			}
		}
		if (fds[2].revents == POLLOUT) {
			if (!p->is_blob.len) {
				switch (apk_istream_get_all(p->is, &p->is_blob)) {
				case 0:
					break;
				case -APKE_EOF:
					p->is_eof = 1;
					goto stdin_close;
				default:
					goto stdin_close;
				}
			}
			int n = write(p->pipe_stdin[1], p->is_blob.ptr, p->is_blob.len);
			if (n < 0) {
				if (errno == EWOULDBLOCK) break;
				goto stdin_close;
			}
			p->is_blob.ptr += n;
			p->is_blob.len -= n;
		}
		if (fds[2].revents & POLLERR) {
		stdin_close:
			close_fd(&p->pipe_stdin[1]);
			fds[2].fd = -1;
		}
	}
	return apk_process_cleanup(p);
}

int apk_process_cleanup(struct apk_process *p)
{
	char buf[APK_EXIT_STATUS_MAX_SIZE];
	int status = 0;

	if (p->is) apk_istream_close(p->is);
	close_fd(&p->pipe_stdin[1]);
	close_fd(&p->pipe_stdout[0]);
	close_fd(&p->pipe_stderr[0]);

	while (waitpid(p->pid, &status, 0) < 0 && errno == EINTR);

	if (apk_exit_status_str(status, buf, sizeof buf)) {
		apk_err(p->out, "%s: %s", p->argv0, buf);
		return -1;
	}
	if (p->is && !p->is_eof) return -2;
	return 0;
}
