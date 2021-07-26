/* extract_v3.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "apk_context.h"
#include "apk_extract.h"

int apk_extract_v3(struct apk_extract_ctx *ectx, struct apk_istream *is)
{
	return apk_istream_close_error(is, -APKE_FORMAT_NOT_SUPPORTED);
}
