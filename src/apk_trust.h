/* apk_trust.h - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2020 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef APK_TRUST
#define APK_TRUST

#include "apk_blob.h"
#include "apk_crypto.h"

struct apk_trust_key {
	struct list_head key_node;
	struct apk_pkey key;
	char *filename;

};

struct apk_trust {
	struct apk_digest_ctx dctx;
	struct list_head trusted_key_list;
	struct list_head private_key_list;
	int allow_untrusted : 1;
	int initialized : 1;
};

int apk_trust_init(struct apk_trust *trust, int keysfd, struct apk_string_array *);
void apk_trust_free(struct apk_trust *trust);
struct apk_pkey *apk_trust_key_by_name(struct apk_trust *trust, const char *filename);

#endif
