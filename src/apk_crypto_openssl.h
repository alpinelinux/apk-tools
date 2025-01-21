/* apk_crypto_openssl.h - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <openssl/evp.h>

struct apk_digest_ctx {
	EVP_MD_CTX *mdctx;
	uint8_t alg;
};

struct apk_pkey {
	uint8_t id[16];
	EVP_PKEY *key;
};
