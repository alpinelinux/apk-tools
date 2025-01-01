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

#define HEXDGT	BIT(APK_CTYPE_HEXDIGIT)
#define PKGNAME	BIT(APK_CTYPE_PACKAGE_NAME)|BIT(APK_CTYPE_DEPENDENCY_NAME)
#define VERSUF	BIT(APK_CTYPE_VERSION_SUFFIX)
#define DEPNAME	BIT(APK_CTYPE_DEPENDENCY_NAME)
#define DEPCOMP	BIT(APK_CTYPE_DEPENDENCY_COMPARER)
#define DEPSEP	BIT(APK_CTYPE_DEPENDENCY_SEPARATOR)
#define REPOSEP	BIT(APK_CTYPE_REPOSITORY_SEPARATOR)
#define VARNAME	BIT(APK_CTYPE_VARIABLE_NAME)

static uint8_t apk_ctype[128] = {
	['\t'] = REPOSEP,
	['\n'] = DEPSEP,
	[' '] = REPOSEP|DEPSEP,
	['+'] = PKGNAME,
	[','] = DEPNAME,
	['-'] = PKGNAME,
	['.'] = PKGNAME,
	[':'] = DEPNAME,
	['<'] = DEPCOMP,
	['='] = DEPCOMP,
	['>'] = DEPCOMP,
	['/'] = DEPNAME,
	['0'] = HEXDGT|PKGNAME|VARNAME,
	['1'] = HEXDGT|PKGNAME|VARNAME,
	['2'] = HEXDGT|PKGNAME|VARNAME,
	['3'] = HEXDGT|PKGNAME|VARNAME,
	['4'] = HEXDGT|PKGNAME|VARNAME,
	['5'] = HEXDGT|PKGNAME|VARNAME,
	['6'] = HEXDGT|PKGNAME|VARNAME,
	['7'] = HEXDGT|PKGNAME|VARNAME,
	['8'] = HEXDGT|PKGNAME|VARNAME,
	['9'] = HEXDGT|PKGNAME|VARNAME,
	['A'] = PKGNAME|VARNAME,
	['B'] = PKGNAME|VARNAME,
	['C'] = PKGNAME|VARNAME,
	['D'] = PKGNAME|VARNAME,
	['E'] = PKGNAME|VARNAME,
	['F'] = PKGNAME|VARNAME,
	['G'] = PKGNAME|VARNAME,
	['H'] = PKGNAME|VARNAME,
	['I'] = PKGNAME|VARNAME,
	['J'] = PKGNAME|VARNAME,
	['K'] = PKGNAME|VARNAME,
	['L'] = PKGNAME|VARNAME,
	['M'] = PKGNAME|VARNAME,
	['N'] = PKGNAME|VARNAME,
	['O'] = PKGNAME|VARNAME,
	['P'] = PKGNAME|VARNAME,
	['Q'] = PKGNAME|VARNAME,
	['R'] = PKGNAME|VARNAME,
	['S'] = PKGNAME|VARNAME,
	['T'] = PKGNAME|VARNAME,
	['U'] = PKGNAME|VARNAME,
	['V'] = PKGNAME|VARNAME,
	['W'] = PKGNAME|VARNAME,
	['X'] = PKGNAME|VARNAME,
	['Y'] = PKGNAME|VARNAME,
	['Z'] = PKGNAME|VARNAME,
	['['] = DEPNAME,
	[']'] = DEPNAME,
	['_'] = PKGNAME|VARNAME,
	['a'] = HEXDGT|VERSUF|PKGNAME|VARNAME,
	['b'] = HEXDGT|VERSUF|PKGNAME|VARNAME,
	['c'] = HEXDGT|VERSUF|PKGNAME|VARNAME,
	['d'] = HEXDGT|VERSUF|PKGNAME|VARNAME,
	['e'] = HEXDGT|VERSUF|PKGNAME|VARNAME,
	['f'] = HEXDGT|VERSUF|PKGNAME|VARNAME,
	['g'] = VERSUF|PKGNAME|VARNAME,
	['h'] = VERSUF|PKGNAME|VARNAME,
	['i'] = VERSUF|PKGNAME|VARNAME,
	['j'] = VERSUF|PKGNAME|VARNAME,
	['k'] = VERSUF|PKGNAME|VARNAME,
	['l'] = VERSUF|PKGNAME|VARNAME,
	['m'] = VERSUF|PKGNAME|VARNAME,
	['n'] = VERSUF|PKGNAME|VARNAME,
	['o'] = VERSUF|PKGNAME|VARNAME,
	['p'] = VERSUF|PKGNAME|VARNAME,
	['q'] = VERSUF|PKGNAME|VARNAME,
	['r'] = VERSUF|PKGNAME|VARNAME,
	['s'] = VERSUF|PKGNAME|VARNAME,
	['t'] = VERSUF|PKGNAME|VARNAME,
	['u'] = VERSUF|PKGNAME|VARNAME,
	['v'] = VERSUF|PKGNAME|VARNAME,
	['w'] = VERSUF|PKGNAME|VARNAME,
	['x'] = VERSUF|PKGNAME|VARNAME,
	['y'] = VERSUF|PKGNAME|VARNAME,
	['z'] = VERSUF|PKGNAME|VARNAME,
	['~'] = DEPCOMP,
};

int apk_blob_spn(apk_blob_t blob, unsigned char ctype, apk_blob_t *l, apk_blob_t *r)
{
	uint8_t mask = BIT(ctype);
	int i, ret = 0;

	for (i = 0; i < blob.len; i++) {
		uint8_t ch = blob.ptr[i];
		if (ch >= ARRAY_SIZE(apk_ctype) || !(apk_ctype[ch]&mask)) {
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
		if (ch < ARRAY_SIZE(apk_ctype) && (apk_ctype[ch]&mask)) {
			ret = 1;
			break;
		}
	}
	if (l != NULL) *l = APK_BLOB_PTR_LEN(blob.ptr, i);
	if (r != NULL) *r = APK_BLOB_PTR_LEN(blob.ptr+i, blob.len-i);
	return ret;
}
