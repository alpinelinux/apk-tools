/* app_verify.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include "apk_applet.h"
#include "apk_database.h"
#include "apk_print.h"

static int verify_main(void *ctx, struct apk_database *db, struct apk_string_array *args)
{
	struct apk_sign_ctx sctx;
	char **parg;
	int r, rc = 0;

	foreach_array_item(parg, args) {
		apk_sign_ctx_init(&sctx, APK_SIGN_VERIFY, NULL, db->keys_fd);
		r = apk_tar_parse(
			apk_istream_gunzip_mpart(apk_istream_from_file(AT_FDCWD, *parg),
						 apk_sign_ctx_mpart_cb, &sctx),
			apk_sign_ctx_verify_tar, &sctx, &db->id_cache);
		r = apk_sign_ctx_status(&sctx, r);
		apk_sign_ctx_free(&sctx);
		if (r != 0) rc++;
		if (apk_verbosity >= 1) {
			const char *msg = "OK";
			if (r == -ENOKEY) {
				msg = "UNTRUSTED";
				r = 0;
			} else if (r < 0) msg = apk_error_str(r);
			apk_message("%s: %d - %s", *parg, r, msg);
		} else if (r != 0)
			printf("%s\n", *parg);
	}

	return rc;
}

static struct apk_applet apk_verify = {
	.name = "verify",
	.open_flags = APK_OPENF_READ | APK_OPENF_NO_STATE,
	.main = verify_main,
};

APK_DEFINE_APPLET(apk_verify);

