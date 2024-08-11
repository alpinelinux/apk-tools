/* app_vertest.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include <unistd.h>
#include "apk_defines.h"
#include "apk_applet.h"
#include "apk_database.h"
#include "apk_version.h"
#include "apk_print.h"

static int vertest_one(struct apk_ctx *ac, apk_blob_t arg)
{
	struct apk_out *out = &ac->out;
	apk_blob_t ver1, ver2, op, space = APK_BLOB_STRLIT(" "), binvert = APK_BLOB_STRLIT("!");
	int ok = 0, invert = 0;

	// trim comments and trailing whitespace
	apk_blob_split(arg, APK_BLOB_STRLIT("#"), &arg, &op);
	arg = apk_blob_trim(arg);
	if (arg.len == 0) return 0;

	// arguments are either:
	//   "version"		-> check validity
	//   "!version"		-> check invalid
	//   "ver1 op ver2"	-> check if that the comparison is true
	//   "ver1 !op ver2"	-> check if that the comparison is false
	if (apk_blob_split(arg, space, &ver1, &op) &&
	    apk_blob_split(op,  space, &op,   &ver2)) {
		invert = apk_blob_pull_blob_match(&op, binvert);
		ok = apk_version_match(ver1, apk_version_result_mask_blob(op), ver2);
	} else {
		ver1 = arg;
		invert = apk_blob_pull_blob_match(&ver1, binvert);
		ok = apk_version_validate(ver1);
	}
	if (invert) ok = !ok;
	if (!ok) {
		apk_msg(out, "FAIL: " BLOB_FMT, BLOB_PRINTF(arg));
		return 1;
	}

	apk_dbg(out, "OK: " BLOB_FMT, BLOB_PRINTF(arg));
	return 0;
}

static int vertest_main(void *pctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	struct apk_istream *is;
	char **parg;
	apk_blob_t l;
	int errors = 0, count = 0;

	if (apk_array_len(args) != 0) {
		foreach_array_item(parg, args)
			errors += vertest_one(ac, APK_BLOB_STR(*parg));
		count = apk_array_len(args);
	} else {
		is = apk_istream_from_fd(STDIN_FILENO);
		if (IS_ERR(is)) return 1;

		while (apk_istream_get_delim(is, APK_BLOB_STR("\n"), &l) == 0) {
			errors += vertest_one(ac, l);
			count++;
		}

		if (apk_istream_close(is) != 0)
			errors++;
	}
	if (errors) apk_dbg(&ac->out, "Result: %d/%d", count-errors, count);

	return errors ? 1 : 0;
}

static struct apk_applet apk_vertest = {
	.name = "vertest",
	.main = vertest_main,
};

APK_DEFINE_APPLET(apk_vertest);
