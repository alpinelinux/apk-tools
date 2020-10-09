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
	apk_string_array_init(&ac->private_keys);
	apk_out_reset(&ac->out);
	ac->out.out = stdout;
	ac->out.err = stderr;
	ac->out.verbosity = 1;
}

void apk_ctx_free(struct apk_ctx *ac)
{
	apk_id_cache_free(&ac->id_cache);
	apk_trust_free(&ac->trust);
	apk_string_array_free(&ac->repository_list);
	apk_string_array_free(&ac->private_keys);
}

int apk_ctx_prepare(struct apk_ctx *ac)
{
	if (ac->flags & APK_SIMULATE &&
	    ac->open_flags & (APK_OPENF_CREATE | APK_OPENF_WRITE)) {
		ac->open_flags &= ~(APK_OPENF_CREATE | APK_OPENF_WRITE);
		ac->open_flags |= APK_OPENF_READ;
	}
	if (!ac->cache_dir) ac->cache_dir = "etc/apk/cache";
	if (!ac->keys_dir) ac->keys_dir = "etc/apk/keys";
	if (!ac->root) ac->root = "/";
	if (!ac->cache_max_age) ac->cache_max_age = 4*60*60; /* 4 hours default */

	ac->root_fd = openat(AT_FDCWD, ac->root, O_RDONLY | O_CLOEXEC);
	if (ac->root_fd < 0 && (ac->open_flags & APK_OPENF_CREATE)) {
		mkdirat(AT_FDCWD, ac->root, 0755);
		ac->root_fd = openat(AT_FDCWD, ac->root, O_RDONLY | O_CLOEXEC);
	}
	if (ac->root_fd < 0) {
		apk_err(&ac->out, "Unable to open root: %s", apk_error_str(errno));
		return -errno;
	}
	return 0;
}

struct apk_trust *apk_ctx_get_trust(struct apk_ctx *ac)
{
	if (!ac->trust.mdctx) {
		int r = apk_trust_init(&ac->trust,
			openat(ac->root_fd, ac->keys_dir, O_RDONLY | O_CLOEXEC),
			ac->private_keys);
		if (r) return ERR_PTR(r);
		ac->trust.allow_untrusted = !!(ac->flags & APK_ALLOW_UNTRUSTED);
	}
	return &ac->trust;
}

struct apk_id_cache *apk_ctx_get_id_cache(struct apk_ctx *ac)
{
	if (!ac->id_cache.root_fd)
		apk_id_cache_init(&ac->id_cache, apk_ctx_fd_root(ac));
	return &ac->id_cache;
}
