/* context.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2020 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include "apk_context.h"

void apk_ctx_init(struct apk_ctx *ac)
{
	memset(ac, 0, sizeof *ac);
	apk_string_array_init(&ac->repository_list);
	apk_trust_init(&ac->trust);
	apk_out_reset(&ac->out);
	ac->out.out = stdout;
	ac->out.err = stderr;
	ac->out.verbosity = 1;
	apk_digest_ctx_init(&ac->dctx, APK_DIGEST_SHA256);
}

void apk_ctx_free(struct apk_ctx *ac)
{
	apk_id_cache_free(&ac->id_cache);
	apk_trust_free(&ac->trust);
	apk_string_array_free(&ac->repository_list);
	if (ac->out.log) fclose(ac->out.log);
}

int apk_ctx_prepare(struct apk_ctx *ac)
{
	if (ac->flags & APK_SIMULATE &&
	    ac->open_flags & (APK_OPENF_CREATE | APK_OPENF_WRITE)) {
		ac->open_flags &= ~(APK_OPENF_CREATE | APK_OPENF_WRITE);
		ac->open_flags |= APK_OPENF_READ;
	}
	if (ac->flags & APK_ALLOW_UNTRUSTED) ac->trust.allow_untrusted = 1;
	if (!ac->cache_dir) ac->cache_dir = "etc/apk/cache";
	if (!ac->keys_dir) ac->keys_dir = "etc/apk/keys";
	if (!ac->root) ac->root = "/";
	if (!ac->cache_max_age) ac->cache_max_age = 4*60*60; /* 4 hours default */

	if (!strcmp(ac->root, "/")) {
		// No chroot needed if using system root
		ac->flags |= APK_NO_CHROOT;

		// Check uvol availability
		ac->uvol = getenv("APK_UVOL") ?: "/usr/bin/uvol";
		if (access(ac->uvol, X_OK) != 0)
			ac->uvol = ERR_PTR(-APKE_UVOL_NOT_AVAILABLE);
	} else {
		ac->uvol = ERR_PTR(-APKE_UVOL_ROOT);
	}


	ac->root_fd = openat(AT_FDCWD, ac->root, O_RDONLY | O_CLOEXEC);
	if (ac->root_fd < 0 && (ac->open_flags & APK_OPENF_CREATE)) {
		mkdirat(AT_FDCWD, ac->root, 0755);
		ac->root_fd = openat(AT_FDCWD, ac->root, O_RDONLY | O_CLOEXEC);
	}
	if (ac->root_fd < 0) {
		apk_err(&ac->out, "Unable to open root: %s", apk_error_str(errno));
		return -errno;
	}
	ac->dest_fd = ac->root_fd;

	if (ac->open_flags & APK_OPENF_WRITE) {
		const char *log_path = "var/log/apk.log";
		const int lflags = O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC;
		int fd = openat(ac->root_fd, log_path, lflags, 0644);
		if (fd < 0 && (ac->open_flags & APK_OPENF_CREATE)) {
			mkdirat(ac->root_fd, "var", 0755);
			mkdirat(ac->root_fd, "var/log", 0755);
			fd = openat(ac->root_fd, log_path, lflags, 0644);
		}
		if (fd < 0) {
			apk_err(&ac->out, "Unable to open log: %s", apk_error_str(errno));
			return -errno;
		}
		ac->out.log = fdopen(fd, "a");
	}
	return 0;
}

struct apk_trust *apk_ctx_get_trust(struct apk_ctx *ac)
{
	if (!ac->trust.keys_loaded) {
		int r = apk_trust_load_keys(&ac->trust,
			openat(ac->root_fd, ac->keys_dir, O_RDONLY | O_CLOEXEC));
		if (r != 0) apk_err(&ac->out, "Unable to load trust keys: %s", apk_error_str(r));
	}
	return &ac->trust;
}

struct apk_id_cache *apk_ctx_get_id_cache(struct apk_ctx *ac)
{
	if (!ac->id_cache.root_fd)
		apk_id_cache_init(&ac->id_cache, apk_ctx_fd_root(ac));
	return &ac->id_cache;
}
