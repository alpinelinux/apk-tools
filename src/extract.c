/* extract.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <spawn.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/xattr.h>

#include "apk_context.h"
#include "apk_extract.h"

static int uvol_run(struct apk_ctx *ac, char *action, const char *volname, char *arg1, char *arg2)
{
	struct apk_out *out = &ac->out;
	pid_t pid;
	int r, status;
	char *argv[] = { (char*)apk_ctx_get_uvol(ac), action, (char*) volname, arg1, arg2, 0 };
	posix_spawn_file_actions_t act;

	posix_spawn_file_actions_init(&act);
	posix_spawn_file_actions_addclose(&act, STDIN_FILENO);
	r = posix_spawn(&pid, apk_ctx_get_uvol(ac), &act, 0, argv, environ);
	posix_spawn_file_actions_destroy(&act);
	if (r != 0) {
		apk_err(out, "%s: uvol exec error: %s", volname, apk_error_str(r));
		return r;
	}
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		apk_err(out, "%s: uvol exited with error %d", volname, WEXITSTATUS(status));
		return -APKE_UVOL;
	}
	return 0;
}

static int uvol_extract(struct apk_ctx *ac, const char *volname, char *arg1, off_t sz,
	struct apk_istream *is, apk_progress_cb cb, void *cb_ctx)
{
	struct apk_out *out = &ac->out;
	struct apk_ostream *os;
	pid_t pid;
	int r, status, pipefds[2];
	char *argv[] = { (char*)apk_ctx_get_uvol(ac), "write", (char*) volname, arg1, 0 };
	posix_spawn_file_actions_t act;

	if (pipe2(pipefds, O_CLOEXEC) != 0) return -errno;

	posix_spawn_file_actions_init(&act);
	posix_spawn_file_actions_adddup2(&act, pipefds[0], STDIN_FILENO);
	r = posix_spawn(&pid, apk_ctx_get_uvol(ac), &act, 0, argv, environ);
	posix_spawn_file_actions_destroy(&act);
	if (r != 0) {
		apk_err(out, "%s: uvol exec error: %s", volname, apk_error_str(r));
		return r;
	}
	close(pipefds[0]);
	os = apk_ostream_to_fd(pipefds[1]);
	apk_stream_copy(is, os, sz, cb, cb_ctx, 0);
	r = apk_ostream_close(os);
	if (r != 0) {
		if (r >= 0) r = -APKE_UVOL;
		apk_err(out, "%s: uvol write error: %s", volname, apk_error_str(r));
		return r;
	}

	while (waitpid(pid, &status, 0) < 0 && errno == EINTR);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		apk_err(out, "%s: uvol exited with error %d", volname, WEXITSTATUS(status));
		return -APKE_UVOL;
	}

	return 0;
}

static int apk_extract_volume(struct apk_ctx *ac, const struct apk_file_info *fi,
	struct apk_istream *is, apk_progress_cb cb, void *cb_ctx)
{
	char size[64];
	int r;

	snprintf(size, sizeof size, "%ju", fi->size);
	r = uvol_run(ac, "create", fi->uvol_name, size, "ro");
	if (r != 0) return r;

	r = uvol_extract(ac, fi->uvol_name, size, fi->size, is, cb, cb_ctx);
	if (r == 0) r = uvol_run(ac, "up", fi->uvol_name, 0, 0);
	if (r != 0) uvol_run(ac, "remove", fi->uvol_name, 0, 0);
	return r;
}

int apk_extract_file(int atfd, const struct apk_file_info *ae,
		const char *extract_name, const char *link_target,
		struct apk_istream *is,
		apk_progress_cb cb, void *cb_ctx,
		unsigned int extract_flags, struct apk_ctx *ac)
{
	struct apk_out *out = &ac->out;
	struct apk_xattr *xattr;
	const char *fn = extract_name ?: ae->name;
	int fd, r = -1, atflags = 0, ret = 0;

	if (ae->uvol_name && is) {
		if (extract_name || link_target) return -APKE_UVOL;
		return apk_extract_volume(ac, ae, is, cb, cb_ctx);
	}

	if (!S_ISDIR(ae->mode) && !(extract_flags & APK_EXTRACTF_NO_OVERWRITE)) {
		if (unlinkat(atfd, fn, 0) != 0 && errno != ENOENT) return -errno;
	}

	switch (ae->mode & S_IFMT) {
	case S_IFDIR:
		r = mkdirat(atfd, fn, ae->mode & 07777);
		if (r < 0 && errno != EEXIST)
			ret = -errno;
		break;
	case S_IFREG:
		if (ae->link_target == NULL) {
			int flags = O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC | O_EXCL;
			int fd = openat(atfd, fn, flags, ae->mode & 07777);
			if (fd < 0) {
				ret = -errno;
				break;
			}
			struct apk_ostream *os = apk_ostream_to_fd(fd);
			if (IS_ERR(os)) {
				ret = PTR_ERR(os);
				break;
			}
			apk_stream_copy(is, os, ae->size, cb, cb_ctx, 0);
			r = apk_ostream_close(os);
			if (r < 0) {
				unlinkat(atfd, fn, 0);
				ret = r;
			}
		} else {
			r = linkat(atfd, link_target ?: ae->link_target, atfd, fn, 0);
			if (r < 0) ret = -errno;
		}
		break;
	case S_IFLNK:
		r = symlinkat(link_target ?: ae->link_target, atfd, fn);
		if (r < 0) ret = -errno;
		atflags |= AT_SYMLINK_NOFOLLOW;
		break;
	case S_IFBLK:
	case S_IFCHR:
	case S_IFIFO:
		r = mknodat(atfd, fn, ae->mode, ae->device);
		if (r < 0) ret = -errno;
		break;
	}
	if (ret) {
		apk_err(out, "Failed to create %s: %s", ae->name, strerror(-ret));
		return ret;
	}

	if (!(extract_flags & APK_EXTRACTF_NO_CHOWN)) {
		r = fchownat(atfd, fn, ae->uid, ae->gid, atflags);
		if (r < 0) {
			apk_err(out, "Failed to set ownership on %s: %s",
				fn, strerror(errno));
			if (!ret) ret = -errno;
		}

		/* chown resets suid bit so we need set it again */
		if (ae->mode & 07000) {
			r = fchmodat(atfd, fn, ae->mode & 07777, atflags);
			if (r < 0) {
				apk_err(out, "Failed to set file permissions on %s: %s",
					fn, strerror(errno));
				if (!ret) ret = -errno;
			}
		}
	}

	/* extract xattrs */
	if (!S_ISLNK(ae->mode) && ae->xattrs && ae->xattrs->num) {
		r = 0;
		fd = openat(atfd, fn, O_RDWR);
		if (fd >= 0) {
			foreach_array_item(xattr, ae->xattrs) {
				if (fsetxattr(fd, xattr->name, xattr->value.ptr, xattr->value.len, 0) < 0) {
					r = -errno;
					if (r != -ENOTSUP) break;
				}
			}
			close(fd);
		} else {
			r = -errno;
		}
		if (r) {
			if (r != -ENOTSUP)
				apk_err(out, "Failed to set xattrs on %s: %s",
					fn, strerror(-r));
			if (!ret) ret = r;
		}
	}

	if (!S_ISLNK(ae->mode)) {
		/* preserve modification time */
		struct timespec times[2];

		times[0].tv_sec  = times[1].tv_sec  = ae->mtime;
		times[0].tv_nsec = times[1].tv_nsec = 0;
		r = utimensat(atfd, fn, times, atflags);
		if (r < 0) {
			apk_err(out, "Failed to preserve modification time on %s: %s",
				fn, strerror(errno));
			if (!ret || ret == -ENOTSUP) ret = -errno;
		}
	}

	return ret;
}

int apk_extract(struct apk_extract_ctx *ectx, struct apk_istream *is)
{
	void *sig;

	if (IS_ERR(is)) return PTR_ERR(is);

	sig = apk_istream_peek(is, 4);
	if (IS_ERR(sig)) return apk_istream_close_error(is, PTR_ERR(sig));

	if (memcmp(sig, "ADB", 3) == 0) return apk_extract_v3(ectx, is);
	return apk_extract_v2(ectx, is);
}
