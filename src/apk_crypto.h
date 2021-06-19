/* apk_crypt.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2021 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef APK_CRYPTO_H
#define APK_CRYPTO_H

#include <assert.h>
#include <string.h>
#include <openssl/evp.h>
#include "apk_defines.h"
#include "apk_openssl.h"

// Digest

struct apk_digest_ctx {
	EVP_MD_CTX *mdctx;
	uint8_t alg;
};

#define APK_DIGEST_NONE		0x00
#define APK_DIGEST_MD5		0x01
#define APK_DIGEST_SHA1		0x02
#define APK_DIGEST_SHA256	0x03
#define APK_DIGEST_SHA512	0x04

#define APK_DIGEST_MAX_LENGTH	64	// longest is SHA512

const char *apk_digest_alg_str(uint8_t);
uint8_t apk_digest_alg_from_csum(int);

struct apk_digest {
	uint8_t alg, len;
	uint8_t data[APK_DIGEST_MAX_LENGTH];
};

#define APK_DIGEST_BLOB(d) APK_BLOB_PTR_LEN((void*)((d).data), (d).len)

static inline const EVP_MD *apk_digest_alg_to_evp(uint8_t alg) {
	switch (alg) {
	case APK_DIGEST_NONE:	return EVP_md_null();
	case APK_DIGEST_MD5:	return EVP_md5();
	case APK_DIGEST_SHA1:	return EVP_sha1();
	case APK_DIGEST_SHA256:	return EVP_sha256();
	case APK_DIGEST_SHA512:	return EVP_sha512();
	default:
		assert(alg);
		return EVP_md_null();
	}
}

int apk_digest_alg_len(uint8_t alg);
uint8_t apk_digest_alg_by_len(int len);

static inline int apk_digest_cmp(struct apk_digest *a, struct apk_digest *b) {
	if (a->alg != b->alg) return b->alg - a->alg;
	return memcmp(a->data, b->data, a->len);
}

static inline void apk_digest_reset(struct apk_digest *d) {
	d->alg = APK_DIGEST_NONE;
	d->len = 0;
}

static inline void apk_digest_set(struct apk_digest *d, uint8_t alg) {
	d->alg = alg;
	d->len = apk_digest_alg_len(alg);
}

static inline int apk_digest_calc(struct apk_digest *d, uint8_t alg, const void *ptr, size_t sz)
{
	unsigned int md_sz = sizeof d->data;
	if (EVP_Digest(ptr, sz, d->data, &md_sz, apk_digest_alg_to_evp(alg), 0) != 1)
		return -APKE_CRYPTO_ERROR;
	d->alg = alg;
	d->len = md_sz;
	return 0;
}

static inline int apk_digest_ctx_init(struct apk_digest_ctx *dctx, uint8_t alg) {
	dctx->mdctx = EVP_MD_CTX_new();
	if (!dctx->mdctx) return -ENOMEM;
	dctx->alg = alg;
#ifdef EVP_MD_CTX_FLAG_FINALISE
	EVP_MD_CTX_set_flags(dctx->mdctx, EVP_MD_CTX_FLAG_FINALISE);
#endif
	EVP_DigestInit_ex(dctx->mdctx, apk_digest_alg_to_evp(alg), 0);
	return 0;
}

static inline void apk_digest_ctx_free(struct apk_digest_ctx *dctx) {
	EVP_MD_CTX_free(dctx->mdctx);
	dctx->mdctx = 0;
}

static inline int apk_digest_ctx_update(struct apk_digest_ctx *dctx, const void *ptr, size_t sz) {
	return EVP_DigestUpdate(dctx->mdctx, ptr, sz) == 1 ? 0 : -APKE_CRYPTO_ERROR;
}

static inline int apk_digest_ctx_final(struct apk_digest_ctx *dctx, struct apk_digest *d) {
	unsigned int mdlen = sizeof d->data;
	if (EVP_DigestFinal_ex(dctx->mdctx, d->data, &mdlen) != 1) {
		apk_digest_reset(d);
		return -APKE_CRYPTO_ERROR;
	}
	d->alg = dctx->alg;
	d->len = mdlen;
	return 0;
}

#include "apk_blob.h"
uint8_t apk_digest_from_blob(struct apk_digest *d, apk_blob_t b);
static inline int apk_digest_cmp_csum(const struct apk_digest *d, const struct apk_checksum *csum)
{
	return apk_blob_compare(APK_DIGEST_BLOB(*d), APK_BLOB_CSUM(*csum));
}
static inline void apk_checksum_from_digest(struct apk_checksum *csum, const struct apk_digest *d)
{
	csum->type = d->len;
	memcpy(csum->data, d->data, d->len);
}

// Asymmetric keys

struct apk_pkey {
	uint8_t		id[16];
	EVP_PKEY	*key;
};

int apk_pkey_init(struct apk_pkey *pkey, EVP_PKEY *key);
void apk_pkey_free(struct apk_pkey *pkey);
int apk_pkey_load(struct apk_pkey *pkey, int dirfd, const char *fn);

// Signing

int apk_sign_start(struct apk_digest_ctx *, struct apk_pkey *);
int apk_sign(struct apk_digest_ctx *, void *, size_t *);
int apk_verify_start(struct apk_digest_ctx *, struct apk_pkey *);
int apk_verify(struct apk_digest_ctx *, void *, size_t);

// Initializiation

#if OPENSSL_VERSION_NUMBER < 0x1010000fL || (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2070000fL)

static inline void apk_crypto_cleanup(void)
{
	EVP_cleanup();
#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif
	CRYPTO_cleanup_all_ex_data();
}

static inline void apk_crypto_init(void)
{
	atexit(apk_crypto_cleanup);
	OpenSSL_add_all_algorithms();
#ifndef OPENSSL_NO_ENGINE
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();
#endif
}

#else

static inline void apk_crypto_init(void) {}

#endif

#endif
