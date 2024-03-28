/* apk_blob.h - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef APK_BLOB_H
#define APK_BLOB_H

#include <ctype.h>
#include <string.h>

#include "apk_defines.h"

struct apk_blob {
	long len;
	char *ptr;
};
typedef struct apk_blob apk_blob_t;
typedef int (*apk_blob_cb)(void *ctx, apk_blob_t blob);

#define BLOB_FMT		"%.*s"
#define BLOB_PRINTF(b)		(int)(b).len, (b).ptr

#define APK_CHECKSUM_NONE	0
#define APK_CHECKSUM_MD5	16
#define APK_CHECKSUM_SHA1	20
#define APK_CHECKSUM_DEFAULT	APK_CHECKSUM_SHA1
#define APK_CHECKSUM_MAX	APK_CHECKSUM_SHA1

/* Enough space for a hexdump of the longest checksum possible plus
 * a two-character type prefix */
#define APK_BLOB_CHECKSUM_BUF	(2 + (2 * APK_CHECKSUM_MAX))

/* Internal container for checksums */
struct apk_checksum {
	unsigned char data[APK_CHECKSUM_MAX];
	unsigned char type;
};

#define APK_BLOB_IS_NULL(blob)		((blob).ptr == NULL)

#define APK_BLOB_NULL			((apk_blob_t){0, NULL})
#define APK_BLOB_BUF(buf)		((apk_blob_t){sizeof(buf), (char *)(buf)})
#define APK_BLOB_CSUM(csum)		((apk_blob_t){(csum).type, (char *)(csum).data})
#define APK_BLOB_STRUCT(s)		((apk_blob_t){sizeof(s), (char*)&(s)})
#define APK_BLOB_STRLIT(s)		((apk_blob_t){sizeof(s)-1, (char *)(s)})
#define APK_BLOB_PTR_LEN(beg,len)	((apk_blob_t){(len), (beg)})
#define APK_BLOB_PTR_PTR(beg,end)	APK_BLOB_PTR_LEN((beg),(end)-(beg)+1)

static inline apk_blob_t APK_BLOB_STR(const char *str)
{
	if (str == NULL)
		return APK_BLOB_NULL;
	return ((apk_blob_t){strlen(str), (void *)(str)});
}

static inline apk_blob_t apk_blob_trim(apk_blob_t blob)
{
	apk_blob_t b = blob;
	while (b.len > 0 && isspace(b.ptr[b.len-1]))
		b.len--;
	return b;
}

char *apk_blob_cstr(apk_blob_t str);
apk_blob_t apk_blob_dup(apk_blob_t blob);
int apk_blob_split(apk_blob_t blob, apk_blob_t split, apk_blob_t *l, apk_blob_t *r);
int apk_blob_rsplit(apk_blob_t blob, char split, apk_blob_t *l, apk_blob_t *r);
apk_blob_t apk_blob_pushed(apk_blob_t buffer, apk_blob_t left);
unsigned long apk_blob_hash_seed(apk_blob_t, unsigned long seed);
unsigned long apk_blob_hash(apk_blob_t str);
int apk_blob_compare(apk_blob_t a, apk_blob_t b);
int apk_blob_sort(apk_blob_t a, apk_blob_t b);
int apk_blob_starts_with(apk_blob_t a, apk_blob_t b);
int apk_blob_ends_with(apk_blob_t str, apk_blob_t suffix);
int apk_blob_for_each_segment(apk_blob_t blob, const char *split,
			      apk_blob_cb cb, void *ctx);

static inline char *apk_blob_chr(apk_blob_t b, unsigned char ch)
{
	return memchr(b.ptr, ch, b.len);
}

void apk_blob_push_blob(apk_blob_t *to, apk_blob_t literal);
void apk_blob_push_uint(apk_blob_t *to, unsigned int value, int radix);
void apk_blob_push_csum(apk_blob_t *to, struct apk_checksum *csum);
void apk_blob_push_base64(apk_blob_t *to, apk_blob_t binary);
void apk_blob_push_hexdump(apk_blob_t *to, apk_blob_t binary);
void apk_blob_push_fmt(apk_blob_t *to, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

void apk_blob_pull_char(apk_blob_t *b, int expected);
uint64_t apk_blob_pull_uint(apk_blob_t *b, int radix);
void apk_blob_pull_csum(apk_blob_t *b, struct apk_checksum *csum);
void apk_blob_pull_base64(apk_blob_t *b, apk_blob_t to);
void apk_blob_pull_hexdump(apk_blob_t *b, apk_blob_t to);
int apk_blob_pull_blob_match(apk_blob_t *b, apk_blob_t match);

#endif
