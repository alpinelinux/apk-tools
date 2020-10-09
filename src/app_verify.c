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

static int verify_main(void *ctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	struct apk_out *out = &ac->out;
	struct apk_sign_ctx sctx;
	struct apk_id_cache *idc = apk_ctx_get_id_cache(ac);
	struct apk_trust *trust = apk_ctx_get_trust(ac);
	char **parg;
	int r, ok, rc = 0;

	trust->allow_untrusted = 1;

	foreach_array_item(parg, args) {
		apk_sign_ctx_init(&sctx, APK_SIGN_VERIFY, NULL, trust);
		r = apk_tar_parse(
			apk_istream_gunzip_mpart(apk_istream_from_file(AT_FDCWD, *parg),
						 apk_sign_ctx_mpart_cb, &sctx),
			apk_sign_ctx_verify_tar, &sctx, idc);
		ok = sctx.control_verified && sctx.data_verified;
		if (apk_out_verbosity(out) >= 1)
			apk_msg(out, "%s: %d - %s", *parg, r,
				r < 0 ? apk_error_str(r) :
				ok ? "OK" :
				!sctx.control_verified ? "UNTRUSTED" : "FAILED");
		else if (!ok)
			apk_out(out, "%s", *parg);
		if (!ok)
			rc++;

		apk_sign_ctx_free(&sctx);
	}

	return rc;
}

static struct apk_applet apk_verify = {
	.name = "verify",
	.main = verify_main,
};

APK_DEFINE_APPLET(apk_verify);

