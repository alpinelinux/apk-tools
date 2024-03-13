/* apk_ctype.h - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2024 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef APK_CTYPE_H
#define APK_CTYPE_H

enum {
	APK_CTYPE_HEXDIGIT = 0,
	APK_CTYPE_PACKAGE_NAME,
	APK_CTYPE_VERSION_SUFFIX,
	APK_CTYPE_DEPENDENCY_NAME,
	APK_CTYPE_DEPENDENCY_COMPARER,
	APK_CTYPE_DEPENDENCY_SEPARATOR,
	APK_CTYPE_REPOSITORY_SEPARATOR,
};

int apk_blob_spn(apk_blob_t blob, unsigned char ctype, apk_blob_t *l, apk_blob_t *r);
int apk_blob_cspn(apk_blob_t blob, unsigned char ctype, apk_blob_t *l, apk_blob_t *r);

#endif
