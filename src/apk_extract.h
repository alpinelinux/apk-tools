/* apk_extract.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2021 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef APK_EXTRACT
#define APK_EXTRACT

#include "apk_crypto.h"
#include "apk_print.h"
#include "apk_io.h"

struct apk_ctx;
struct apk_extract_ctx;

#define APK_EXTRACTF_NO_CHOWN		0x0001
#define APK_EXTRACTF_NO_OVERWRITE	0x0002

int apk_extract_file(int atfd, const struct apk_file_info *ae,
		const char *extract_name, const char *hardlink_name,
		struct apk_istream *is,
		apk_progress_cb cb, void *cb_ctx, struct apk_digest_ctx *dctx,
		unsigned int extract_flags, struct apk_out *out);


typedef int (*apk_extract_cb)(struct apk_extract_ctx *,
		const struct apk_file_info *ae,
		struct apk_istream *istream);

struct apk_extract_ctx {
	struct apk_ctx *ac;
	apk_extract_cb cb;
	struct apk_checksum *identity;
	unsigned generate_identity : 1;
	unsigned metadata : 1;
	unsigned metadata_verified : 1;
	void *pctx;
};

static inline void apk_extract_init(struct apk_extract_ctx *ectx, struct apk_ctx *ac, apk_extract_cb cb) {
	*ectx = (struct apk_extract_ctx){.ac = ac, .cb = cb};
}
static inline void apk_extract_reset(struct apk_extract_ctx *ectx) {
	apk_extract_init(ectx, ectx->ac, ectx->cb);
}
static inline void apk_extract_generate_identity(struct apk_extract_ctx *ctx, struct apk_checksum *id) {
	ctx->identity = id;
	ctx->generate_identity = 1;
}
static inline void apk_extract_verify_identity(struct apk_extract_ctx *ctx, struct apk_checksum *id) {
	ctx->identity = id;
}
int apk_extract(struct apk_extract_ctx *, struct apk_istream *is);

int apk_extract_v2(struct apk_extract_ctx *, struct apk_istream *is);
void apk_extract_v2_control(struct apk_extract_ctx *, apk_blob_t, apk_blob_t);

int apk_extract_v3(struct apk_extract_ctx *, struct apk_istream *is);

#endif
