/* apk_trust.h - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2020 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef APK_TRUST
#define APK_TRUST

#include <openssl/evp.h>
#include "apk_blob.h"

struct apk_pkey {
	uint8_t		id[16];
	EVP_PKEY	*key;
};

int apk_pkey_init(struct apk_pkey *pkey, EVP_PKEY *key);
void apk_pkey_free(struct apk_pkey *pkey);
int apk_pkey_load(struct apk_pkey *pkey, int dirfd, const char *fn);

struct apk_trust_key {
	struct list_head key_node;
	struct apk_pkey key;
	char *filename;

};

struct apk_trust {
	EVP_MD_CTX *mdctx;
	struct list_head trusted_key_list;
	struct list_head private_key_list;
	int allow_untrusted : 1;
};

int apk_trust_init(struct apk_trust *trust, int keysfd, struct apk_string_array *);
void apk_trust_free(struct apk_trust *trust);
struct apk_pkey *apk_trust_key_by_name(struct apk_trust *trust, const char *filename);

#endif
