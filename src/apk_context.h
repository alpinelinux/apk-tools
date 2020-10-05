/* apk_context.h - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2020 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef APK_CONTEXT_H
#define APK_CONTEXT_H

#include "apk_print.h"

#define APK_SIMULATE			BIT(0)
#define APK_CLEAN_PROTECTED		BIT(1)
#define APK_RECURSIVE			BIT(2)
#define APK_ALLOW_UNTRUSTED		BIT(3)
#define APK_PURGE			BIT(4)
#define APK_INTERACTIVE			BIT(5)
#define APK_NO_NETWORK			BIT(6)
#define APK_OVERLAY_FROM_STDIN		BIT(7)
#define APK_NO_SCRIPTS			BIT(8)
#define APK_NO_CACHE			BIT(9)
#define APK_NO_COMMIT_HOOKS		BIT(10)

#define APK_FORCE_OVERWRITE		BIT(0)
#define APK_FORCE_OLD_APK		BIT(1)
#define APK_FORCE_BROKEN_WORLD		BIT(2)
#define APK_FORCE_REFRESH		BIT(3)
#define APK_FORCE_NON_REPOSITORY	BIT(4)
#define APK_FORCE_BINARY_STDOUT		BIT(5)

struct apk_ctx {
	unsigned int flags, force, lock_wait;
	struct apk_out out;
	struct apk_progress progress;
	unsigned int cache_max_age;
	unsigned long open_flags;
	const char *root;
	const char *arch;
	const char *keys_dir;
	const char *cache_dir;
	const char *repositories_file;
	struct apk_string_array *repository_list;
	struct apk_string_array *private_keys;
};

void apk_ctx_init(struct apk_ctx *ac);
void apk_ctx_free(struct apk_ctx *ac);

#endif
