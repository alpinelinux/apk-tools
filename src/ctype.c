/* ctype.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2024 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "apk_defines.h"
#include "apk_blob.h"
#include "apk_ctype.h"

#define PKGNAME	BIT(APK_CTYPE_PACKAGE_NAME)|BIT(APK_CTYPE_DEPENDENCY_NAME)
#define VERSUF	BIT(APK_CTYPE_VERSION_SUFFIX)
#define DEPNAME	BIT(APK_CTYPE_DEPENDENCY_NAME)
#define DEPCOMP	BIT(APK_CTYPE_DEPENDENCY_COMPARER)
#define DEPSEP	BIT(APK_CTYPE_DEPENDENCY_SEPARATOR)
#define REPOSEP	BIT(APK_CTYPE_REPOSITORY_SEPARATOR)

static uint8_t apk_ctype[128] = {
	['\t'] = REPOSEP,
	['\n'] = DEPSEP,
	[' '] = REPOSEP|DEPSEP,
	['+'] = PKGNAME,
	['-'] = PKGNAME,
	['.'] = PKGNAME,
	[':'] = REPOSEP|DEPNAME,
	['<'] = DEPCOMP,
	['='] = DEPCOMP,
	['>'] = DEPCOMP,
	['/'] = DEPNAME,
	['0'] = PKGNAME,
	['1'] = PKGNAME,
	['2'] = PKGNAME,
	['3'] = PKGNAME,
	['4'] = PKGNAME,
	['5'] = PKGNAME,
	['6'] = PKGNAME,
	['7'] = PKGNAME,
	['8'] = PKGNAME,
	['9'] = PKGNAME,
	['A'] = PKGNAME,
	['B'] = PKGNAME,
	['C'] = PKGNAME,
	['D'] = PKGNAME,
	['E'] = PKGNAME,
	['F'] = PKGNAME,
	['G'] = PKGNAME,
	['H'] = PKGNAME,
	['I'] = PKGNAME,
	['J'] = PKGNAME,
	['K'] = PKGNAME,
	['L'] = PKGNAME,
	['M'] = PKGNAME,
	['N'] = PKGNAME,
	['O'] = PKGNAME,
	['P'] = PKGNAME,
	['Q'] = PKGNAME,
	['R'] = PKGNAME,
	['S'] = PKGNAME,
	['T'] = PKGNAME,
	['U'] = PKGNAME,
	['V'] = PKGNAME,
	['W'] = PKGNAME,
	['X'] = PKGNAME,
	['Y'] = PKGNAME,
	['Z'] = PKGNAME,
	['_'] = PKGNAME,
	['a'] = VERSUF|PKGNAME,
	['b'] = VERSUF|PKGNAME,
	['c'] = VERSUF|PKGNAME,
	['d'] = VERSUF|PKGNAME,
	['e'] = VERSUF|PKGNAME,
	['f'] = VERSUF|PKGNAME,
	['g'] = VERSUF|PKGNAME,
	['h'] = VERSUF|PKGNAME,
	['i'] = VERSUF|PKGNAME,
	['j'] = VERSUF|PKGNAME,
	['k'] = VERSUF|PKGNAME,
	['l'] = VERSUF|PKGNAME,
	['m'] = VERSUF|PKGNAME,
	['n'] = VERSUF|PKGNAME,
	['o'] = VERSUF|PKGNAME,
	['p'] = VERSUF|PKGNAME,
	['q'] = VERSUF|PKGNAME,
	['r'] = VERSUF|PKGNAME,
	['s'] = VERSUF|PKGNAME,
	['t'] = VERSUF|PKGNAME,
	['u'] = VERSUF|PKGNAME,
	['v'] = VERSUF|PKGNAME,
	['w'] = VERSUF|PKGNAME,
	['x'] = VERSUF|PKGNAME,
	['y'] = VERSUF|PKGNAME,
	['z'] = VERSUF|PKGNAME,
	['~'] = DEPCOMP,
};

int apk_blob_spn(apk_blob_t blob, unsigned char ctype, apk_blob_t *l, apk_blob_t *r)
{
	uint8_t mask = BIT(ctype);
	int i, ret = 0;

	for (i = 0; i < blob.len; i++) {
		uint8_t ch = blob.ptr[i];
		if (ch < ARRAY_SIZE(apk_ctype) && !(apk_ctype[ch]&mask)) {
			ret = 1;
			break;
		}
	}
	if (l != NULL) *l = APK_BLOB_PTR_LEN(blob.ptr, i);
	if (r != NULL) *r = APK_BLOB_PTR_LEN(blob.ptr+i, blob.len-i);
	return ret;
}

int apk_blob_cspn(apk_blob_t blob, unsigned char ctype, apk_blob_t *l, apk_blob_t *r)
{
	uint8_t mask = BIT(ctype);
	int i, ret = 0;

	for (i = 0; i < blob.len; i++) {
		uint8_t ch = blob.ptr[i];
		if (ch >= ARRAY_SIZE(apk_ctype) || (apk_ctype[ch]&mask)) {
			ret = 1;
			break;
		}
	}
	if (l != NULL) *l = APK_BLOB_PTR_LEN(blob.ptr, i);
	if (r != NULL) *r = APK_BLOB_PTR_LEN(blob.ptr+i, blob.len-i);
	return ret;
}
