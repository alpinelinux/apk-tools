/* crypto_mbedtls.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2024 Jonas Jelonek <jelonek.jonas@gmail.com>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include <mbedtls/platform.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>

#ifdef MBEDTLS_PSA_CRYPTO_C
#include <psa/crypto.h>
#endif

#include "apk_crypto.h"

static inline const mbedtls_md_type_t apk_digest_alg_to_mbedtls_type(uint8_t alg) {
	switch (alg) {
	case APK_DIGEST_NONE:	return MBEDTLS_MD_NONE;
	case APK_DIGEST_MD5:	return MBEDTLS_MD_MD5;
	case APK_DIGEST_SHA1:	return MBEDTLS_MD_SHA1;
	case APK_DIGEST_SHA256_160:
	case APK_DIGEST_SHA256:	return MBEDTLS_MD_SHA256;
	case APK_DIGEST_SHA512:	return MBEDTLS_MD_SHA512;
	default:
		assert(!"valid alg");
		return MBEDTLS_MD_NONE;
	}
}

static inline const mbedtls_md_info_t *apk_digest_alg_to_mdinfo(uint8_t alg)
{
	return mbedtls_md_info_from_type(
		apk_digest_alg_to_mbedtls_type(alg)
	);
}

int apk_digest_calc(struct apk_digest *d, uint8_t alg, const void *ptr, size_t sz)
{
	if (mbedtls_md(apk_digest_alg_to_mdinfo(alg), ptr, sz, d->data))
		return -APKE_CRYPTO_ERROR;

	apk_digest_set(d, alg);
	return 0;
}

int apk_digest_ctx_init(struct apk_digest_ctx *dctx, uint8_t alg)
{
	dctx->alg = alg;

	mbedtls_md_init(&dctx->mdctx);
	if (alg == APK_DIGEST_NONE) return 0;
	if (mbedtls_md_setup(&dctx->mdctx, apk_digest_alg_to_mdinfo(alg), 0) ||
		mbedtls_md_starts(&dctx->mdctx))
		return -APKE_CRYPTO_ERROR;

	return 0;
}

int apk_digest_ctx_reset(struct apk_digest_ctx *dctx)
{
	if (dctx->alg == APK_DIGEST_NONE) return 0;
	if (mbedtls_md_starts(&dctx->mdctx)) return -APKE_CRYPTO_ERROR;
	return 0;
}

int apk_digest_ctx_reset_alg(struct apk_digest_ctx *dctx, uint8_t alg)
{
	assert(alg != APK_DIGEST_NONE);

	mbedtls_md_free(&dctx->mdctx);
	dctx->alg = alg;
	dctx->sigver_key = NULL;
	if (mbedtls_md_setup(&dctx->mdctx, apk_digest_alg_to_mdinfo(alg), 0) ||
	    mbedtls_md_starts(&dctx->mdctx))
		return -APKE_CRYPTO_ERROR;

	return 0;
}

void apk_digest_ctx_free(struct apk_digest_ctx *dctx)
{
	mbedtls_md_free(&dctx->mdctx);
}

int apk_digest_ctx_update(struct apk_digest_ctx *dctx, const void *ptr, size_t sz)
{
	assert(dctx->alg != APK_DIGEST_NONE);
	return mbedtls_md_update(&dctx->mdctx, ptr, sz) == 0 ? 0 : -APKE_CRYPTO_ERROR;
}

int apk_digest_ctx_final(struct apk_digest_ctx *dctx, struct apk_digest *d)
{
	assert(dctx->alg != APK_DIGEST_NONE);
	if (mbedtls_md_finish(&dctx->mdctx, d->data)) {
		apk_digest_reset(d);
		return -APKE_CRYPTO_ERROR;
	}
	d->alg = dctx->alg;
	d->len = apk_digest_alg_len(d->alg);
	return 0;
}

static int apk_load_file_at(int dirfd, const char *fn, unsigned char **buf, size_t *n)
{
	struct stat stats;
	size_t size;
	int fd;

	if ((fd = openat(dirfd, fn, O_RDONLY | O_CLOEXEC)) < 0)
		return -errno;

	if (fstat(fd, &stats)) {
		close(fd);
		return -errno;
	}

	size = (size_t)stats.st_size;
	*n = size;

	if (!size || size > APK_KEYFILE_MAX_LENGTH)
		return MBEDTLS_ERR_PK_FILE_IO_ERROR;
	if ((*buf = mbedtls_calloc(1, size + 1)) == NULL)
		return MBEDTLS_ERR_PK_ALLOC_FAILED;

	if (read(fd, *buf, size) != size) {
		close(fd);

		mbedtls_platform_zeroize(*buf, size);
		mbedtls_free(*buf);

		return MBEDTLS_ERR_PK_FILE_IO_ERROR;
	}
	close(fd);

	(*buf)[size] = '\0';

	/* if it's a PEM key increment length since mbedtls requires
	 * buffer to be null-terminated for PEM */
	if (strstr((const char *) *buf, "-----BEGIN ") != NULL) {
		++*n;
	}

	return 0;
}

static int apk_pkey_init(struct apk_pkey *pkey)
{
	unsigned char dig[APK_DIGEST_LENGTH_MAX];
	unsigned char pub[APK_ENC_KEY_MAX_LENGTH] = {};
	unsigned char *c;
	int len, r = -APKE_CRYPTO_ERROR;

	c = pub + APK_ENC_KEY_MAX_LENGTH;

	// key is written backwards into pub starting at c!
	if ((len = mbedtls_pk_write_pubkey(&c, pub, &pkey->key)) < 0) return -APKE_CRYPTO_ERROR;
	if (!mbedtls_md(apk_digest_alg_to_mdinfo(APK_DIGEST_SHA512), c, len, dig)) {
		memcpy(pkey->id, dig, sizeof pkey->id);
		r = 0;
	}

	return r;
}

void apk_pkey_free(struct apk_pkey *pkey)
{
	mbedtls_pk_free(&pkey->key);
}

static int apk_mbedtls_random(void *ctx, unsigned char *out, size_t len)
{
	return (int)getrandom(out, len, 0);
}

#if MBEDTLS_VERSION_NUMBER >= 0x03000000
static inline int apk_mbedtls_parse_privkey(struct apk_pkey *pkey, const unsigned char *buf, size_t blen)
{
	return mbedtls_pk_parse_key(&pkey->key, buf, blen, NULL, 0, apk_mbedtls_random, NULL);
}
static inline int apk_mbedtls_sign(struct apk_digest_ctx *dctx, struct apk_digest *dig,
				   unsigned char *sig, size_t *sig_len)
{
	return mbedtls_pk_sign(&dctx->sigver_key->key, apk_digest_alg_to_mbedtls_type(dctx->alg),
			       (const unsigned char *)&dig->data, dig->len, sig, *sig_len, sig_len,
			       apk_mbedtls_random, NULL);
}
#else
static inline int apk_mbedtls_parse_privkey(struct apk_pkey *pkey, const unsigned char *buf, size_t blen)
{
	return mbedtls_pk_parse_key(&pkey->key, buf, blen, NULL, 0);
}
static inline int apk_mbedtls_sign(struct apk_digest_ctx *dctx, struct apk_digest *dig,
				   unsigned char *sig, size_t *sig_len)
{
	return mbedtls_pk_sign(&dctx->sigver_key->key, apk_digest_alg_to_mbedtls_type(dctx->alg),
			       (const unsigned char *)&dig->data, dig->len, sig, sig_len,
			       apk_mbedtls_random, NULL);
}
#endif

int apk_pkey_load(struct apk_pkey *pkey, int dirfd, const char *fn, int priv)
{
	unsigned char *buf = NULL;
	size_t blen = 0;
	int ret;

	if (apk_load_file_at(dirfd, fn, &buf, &blen))
		return -APKE_CRYPTO_ERROR;

	mbedtls_pk_init(&pkey->key);
	if ((ret = mbedtls_pk_parse_public_key(&pkey->key, buf, blen)) != 0)
		ret = apk_mbedtls_parse_privkey(pkey, buf, blen);

	mbedtls_platform_zeroize(buf, blen);
	mbedtls_free(buf);
	if (ret != 0)
		return -APKE_CRYPTO_KEY_FORMAT;

	return apk_pkey_init(pkey);
}

int apk_sign_start(struct apk_digest_ctx *dctx, uint8_t alg, struct apk_pkey *pkey)
{
	if (apk_digest_ctx_reset_alg(dctx, alg))
		return -APKE_CRYPTO_ERROR;

	dctx->sigver_key = pkey;
	return 0;
}

int apk_sign(struct apk_digest_ctx *dctx, void *sig, size_t *len)
{
	struct apk_digest dig;
	int r = 0;

	if (!dctx->sigver_key)
		return -APKE_CRYPTO_ERROR;

	if (apk_digest_ctx_final(dctx, &dig) || apk_mbedtls_sign(dctx, &dig, sig, len))
		r = -APKE_SIGNATURE_GEN_FAILURE;

	dctx->sigver_key = NULL;
	return r;
}

int apk_verify_start(struct apk_digest_ctx *dctx, uint8_t alg, struct apk_pkey *pkey)
{
	if (apk_digest_ctx_reset_alg(dctx, alg))
		return -APKE_CRYPTO_ERROR;

	dctx->sigver_key = pkey;
	return 0;
}

int apk_verify(struct apk_digest_ctx *dctx, void *sig, size_t len)
{
	struct apk_digest dig;
	int r = 0;

	if (!dctx->sigver_key)
		return -APKE_CRYPTO_ERROR;

	if (apk_digest_ctx_final(dctx, &dig)) {
		r = -APKE_CRYPTO_ERROR;
		goto final;
	}
	if (mbedtls_pk_verify(&dctx->sigver_key->key, apk_digest_alg_to_mbedtls_type(dctx->alg),
			      (const unsigned char *)&dig.data, dig.len, sig, len))
		r = -APKE_SIGNATURE_INVALID;

final:
	dctx->sigver_key = NULL;
	return r;
}

static void apk_crypto_cleanup(void)
{
#ifdef MBEDTLS_PSA_CRYPTO_C
	mbedtls_psa_crypto_free();
#endif
}

void apk_crypto_init(void)
{
	atexit(apk_crypto_cleanup);
	
#ifdef MBEDTLS_PSA_CRYPTO_C
	psa_crypto_init();
#endif
}
