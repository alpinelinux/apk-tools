/* apk_crypto_mbedtls.h - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2024 Jonas Jelonek <jelonek.jonas@gmail.com>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef APK_CRYPTO_MBEDTLS_H
#define APK_CRYPTO_MBEDTLS_H

#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/bignum.h>

struct apk_pkey {
	uint8_t id[16];
	mbedtls_pk_context key;
};

struct apk_digest_ctx {
	mbedtls_md_context_t mdctx;
	struct apk_pkey *sigver_key;
	uint8_t alg;
};

/* based on mbedtls' internal pkwrite.h calculations */
#define APK_ENC_KEY_MAX_LENGTH          (38 + 2 * MBEDTLS_MPI_MAX_SIZE)
/* sane limit for keyfiles with PEM, long keys and maybe comments */
#define APK_KEYFILE_MAX_LENGTH		64000

#endif
