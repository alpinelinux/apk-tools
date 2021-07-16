/* adb_comp.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2021 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "apk_defines.h"
#include "adb.h"

struct apk_istream *adb_decompress(struct apk_istream *is, adb_comp_t *compression)
{
	 adb_comp_t c = -1;

	if (IS_ERR_OR_NULL(is)) return is;

	uint8_t *buf = apk_istream_peek(is, 4);
	if (memcmp(buf, "ADB", 3) == 0) switch (buf[3]) {
	case '.':
		c = ADB_COMP_NONE;
		break;
	case 'd':
		c = ADB_COMP_DEFLATE;
		apk_istream_get(is, 4);
		is = apk_istream_deflate(is);
		break;
	}
	if (c == -1) {
		apk_istream_close(is);
		return ERR_PTR(-APKE_ADB_COMPRESSION);
	}
	if (compression) *compression = c;
	return is;
}

struct apk_ostream *adb_compress(struct apk_ostream *os, adb_comp_t compression)
{
	if (IS_ERR_OR_NULL(os)) return os;
	switch (compression) {
	case ADB_COMP_NONE:
		return os;
	case ADB_COMP_DEFLATE:
		if (apk_ostream_write(os, "ADBd", 4) < 0) goto err;
		return apk_ostream_deflate(os);
	}
err:
	apk_ostream_cancel(os, -APKE_ADB_COMPRESSION);
	return ERR_PTR(apk_ostream_close(os));
}
