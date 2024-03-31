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
#include "apk_print.h"
#include "apk_extract.h"

static int verify_main(void *ctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	struct apk_out *out = &ac->out;
	struct apk_extract_ctx ectx;
	char **parg;
	int r, rc = 0;

	foreach_array_item(parg, args) {
		apk_extract_init(&ectx, ac, 0);
		r = apk_extract(&ectx, apk_istream_from_file(AT_FDCWD, *parg));
		if (apk_out_verbosity(out) >= 1)
			apk_msg(out, "%s: %s", *parg,
				r < 0 ? apk_error_str(r) : "OK");
		else if (r < 0)
			apk_out(out, "%s", *parg);
		if (r < 0) rc++;
	}

	return rc;
}

static struct apk_applet apk_verify_applet = {
	.name = "verify",
	.main = verify_main,
};

APK_DEFINE_APPLET(apk_verify_applet);

