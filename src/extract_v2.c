/* extract_v2.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "apk_context.h"
#include "apk_extract.h"
#include "apk_package.h"
#include "apk_tar.h"

#define APK_SIGN_NONE			0
#define APK_SIGN_VERIFY			1
#define APK_SIGN_VERIFY_IDENTITY	2
#define APK_SIGN_GENERATE		4
#define APK_SIGN_VERIFY_AND_GENERATE	5

struct apk_sign_ctx {
	struct apk_trust *trust;
	int action;
	const EVP_MD *md;
	int num_signatures;
	int control_started : 1;
	int data_started : 1;
	int has_data_checksum : 1;
	int control_verified : 1;
	int data_verified : 1;
	int allow_untrusted : 1;
	char data_checksum[EVP_MAX_MD_SIZE];
	struct apk_checksum identity;
	EVP_MD_CTX *mdctx;

	struct {
		apk_blob_t data;
		EVP_PKEY *pkey;
		char *identity;
	} signature;
};

static void apk_sign_ctx_init(struct apk_sign_ctx *ctx, int action, struct apk_checksum *identity, struct apk_trust *trust)
{
	memset(ctx, 0, sizeof(struct apk_sign_ctx));
	ctx->trust = trust;
	ctx->action = action;
	ctx->allow_untrusted = trust->allow_untrusted;
	switch (action) {
	case APK_SIGN_VERIFY:
		/* If we're only verifing, we're going to start with a
		 * signature section, which we don't need a hash of */
		ctx->md = EVP_md_null();
		break;
	case APK_SIGN_VERIFY_IDENTITY:
		/* If we're checking the package against a particular hash,
		 * we need to start with that hash, because there may not
		 * be a signature section to deduce it from */
		ctx->md = EVP_sha1();
		memcpy(&ctx->identity, identity, sizeof(ctx->identity));
		break;
	case APK_SIGN_GENERATE:
	case APK_SIGN_VERIFY_AND_GENERATE:
		ctx->md = EVP_sha1();
		break;
	default:
		ctx->action = APK_SIGN_NONE;
		ctx->md = EVP_md_null();
		ctx->control_started = 1;
		ctx->data_started = 1;
		break;
	}
	ctx->mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx->mdctx, ctx->md, NULL);
	EVP_MD_CTX_set_flags(ctx->mdctx, EVP_MD_CTX_FLAG_ONESHOT);
}

static void apk_sign_ctx_free(struct apk_sign_ctx *ctx)
{
	if (ctx->signature.data.ptr != NULL)
		free(ctx->signature.data.ptr);
	EVP_MD_CTX_free(ctx->mdctx);
}

static int check_signing_key_trust(struct apk_sign_ctx *sctx)
{
	switch (sctx->action) {
	case APK_SIGN_VERIFY:
	case APK_SIGN_VERIFY_AND_GENERATE:
		if (sctx->signature.pkey == NULL) {
			if (sctx->allow_untrusted)
				break;
			return -APKE_SIGNATURE_UNTRUSTED;
		}
	}
	return 0;
}

static int apk_sign_ctx_process_file(struct apk_sign_ctx *ctx, const struct apk_file_info *fi,
		struct apk_istream *is)
{
	static struct {
		char type[8];
		unsigned int nid;
	} signature_type[] = {
		{ "RSA512", NID_sha512 },
		{ "RSA256", NID_sha256 },
		{ "RSA", NID_sha1 },
		{ "DSA", NID_dsa },
	};
	const EVP_MD *md = NULL;
	const char *name = NULL;
	struct apk_pkey *pkey;
	int r, i;

	if (ctx->data_started)
		return 1;

	if (fi->name[0] != '.' || strchr(fi->name, '/') != NULL) {
		/* APKv1.0 compatibility - first non-hidden file is
		 * considered to start the data section of the file.
		 * This does not make any sense if the file has v2.0
		 * style .PKGINFO */
		if (ctx->has_data_checksum)
			return -APKE_V2PKG_FORMAT;
		/* Error out early if identity part is missing */
		if (ctx->action == APK_SIGN_VERIFY_IDENTITY)
			return -APKE_V2PKG_FORMAT;
		ctx->data_started = 1;
		ctx->control_started = 1;
		r = check_signing_key_trust(ctx);
		if (r < 0)
			return r;
		return 1;
	}

	if (ctx->control_started)
		return 1;

	if (strncmp(fi->name, ".SIGN.", 6) != 0) {
		ctx->control_started = 1;
		return 1;
	}

	/* By this point, we must be handling a signature file */
	ctx->num_signatures++;

	/* Already found a signature by a trusted key; no need to keep searching */
	if ((ctx->action != APK_SIGN_VERIFY &&
	     ctx->action != APK_SIGN_VERIFY_AND_GENERATE) ||
	    ctx->signature.pkey != NULL)
		return 0;

	for (i = 0; i < ARRAY_SIZE(signature_type); i++) {
		size_t slen = strlen(signature_type[i].type);
		if (strncmp(&fi->name[6], signature_type[i].type, slen) == 0 &&
		    fi->name[6+slen] == '.') {
			md = EVP_get_digestbynid(signature_type[i].nid);
			name = &fi->name[6+slen+1];
			break;
		}
	}
	if (!md) return 0;

	pkey = apk_trust_key_by_name(ctx->trust, name);
	if (pkey) {
		ctx->md = md;
		ctx->signature.pkey = pkey->key;
		ctx->signature.data = apk_blob_from_istream(is, fi->size);
	}
	return 0;
}


/*	apk_sign_ctx_mpart_cb() handles hashing archives and checking signatures, but
	it can't do it alone. apk_sign_ctx_process_file() must be in the loop to
	actually select which signature is to be verified and load the corresponding
	public key into the context object, and	apk_sign_ctx_parse_pkginfo_line()
	needs to be called when handling the .PKGINFO file to find any applicable
	datahash and load it into the context for this function to check against. */
static int apk_sign_ctx_mpart_cb(void *ctx, int part, apk_blob_t data)
{
	struct apk_sign_ctx *sctx = (struct apk_sign_ctx *) ctx;
	unsigned char calculated[EVP_MAX_MD_SIZE];
	int r, end_of_control;

	if ((part == APK_MPART_DATA) ||
	    (part == APK_MPART_BOUNDARY && sctx->data_started))
		goto update_digest;

	/* Still in signature blocks? */
	if (!sctx->control_started) {
		if (part == APK_MPART_END)
			return -APKE_V2PKG_FORMAT;
		goto reset_digest;
	}

	/* Grab state and mark all remaining block as data */
	end_of_control = (sctx->data_started == 0);
	sctx->data_started = 1;

	/* End of control-block and control does not have data checksum? */
	if (sctx->has_data_checksum == 0 && end_of_control &&
	    part != APK_MPART_END)
		goto update_digest;

	/* Drool in the remainder of the digest block now, we will finish
	 * hashing it in all cases */
	EVP_DigestUpdate(sctx->mdctx, data.ptr, data.len);

	if (sctx->has_data_checksum && !end_of_control) {
		/* End of data-block with a checksum read from the control block */
		EVP_DigestFinal_ex(sctx->mdctx, calculated, NULL);
		if (EVP_MD_CTX_size(sctx->mdctx) == 0 ||
		    memcmp(calculated, sctx->data_checksum, EVP_MD_CTX_size(sctx->mdctx)) != 0)
			return -APKE_V2PKG_INTEGRITY;
		sctx->data_verified = 1;
		if (!sctx->allow_untrusted && !sctx->control_verified)
			return -APKE_SIGNATURE_UNTRUSTED;
		return 0;
	}

	/* Either end of control block with a data checksum or end
	 * of the data block following a control block without a data
	 * checksum. In either case, we're checking a signature. */
	r = check_signing_key_trust(sctx);
	if (r < 0)
		return r;

	switch (sctx->action) {
	case APK_SIGN_VERIFY:
	case APK_SIGN_VERIFY_AND_GENERATE:
		if (sctx->signature.pkey != NULL) {
			r = EVP_VerifyFinal(sctx->mdctx,
				(unsigned char *) sctx->signature.data.ptr,
				sctx->signature.data.len,
				sctx->signature.pkey);
			if (r != 1 && !sctx->allow_untrusted)
				return -APKE_SIGNATURE_INVALID;
		} else {
			r = 0;
			if (!sctx->allow_untrusted)
				return -APKE_SIGNATURE_UNTRUSTED;
		}
		if (r == 1) {
			sctx->control_verified = 1;
			if (!sctx->has_data_checksum && part == APK_MPART_END)
				sctx->data_verified = 1;
		}
		if (sctx->action == APK_SIGN_VERIFY_AND_GENERATE) goto generate_identity;
		break;
	case APK_SIGN_VERIFY_IDENTITY:
		/* Reset digest for hashing data */
		EVP_DigestFinal_ex(sctx->mdctx, calculated, NULL);
		if (memcmp(calculated, sctx->identity.data,
			   sctx->identity.type) != 0)
			return -APKE_V2PKG_INTEGRITY;
		sctx->control_verified = 1;
		if (!sctx->has_data_checksum && part == APK_MPART_END)
			sctx->data_verified = 1;
		break;
	case APK_SIGN_GENERATE:
	generate_identity:
		/* Package identity is the checksum */
		sctx->identity.type = EVP_MD_CTX_size(sctx->mdctx);
		EVP_DigestFinal_ex(sctx->mdctx, sctx->identity.data, NULL);
		if (!sctx->has_data_checksum) return -APKE_V2PKG_FORMAT;
		break;
	}
reset_digest:
	EVP_DigestInit_ex(sctx->mdctx, sctx->md, NULL);
	EVP_MD_CTX_set_flags(sctx->mdctx, EVP_MD_CTX_FLAG_ONESHOT);
	return 0;

update_digest:
	EVP_MD_CTX_clear_flags(sctx->mdctx, EVP_MD_CTX_FLAG_ONESHOT);
	EVP_DigestUpdate(sctx->mdctx, data.ptr, data.len);
	return 0;
}

static int apk_extract_verify_v2index(struct apk_extract_ctx *ectx, apk_blob_t *desc, struct apk_istream *is)
{
	return 0;
}

static int apk_extract_verify_v2file(struct apk_extract_ctx *ectx, const struct apk_file_info *fi, struct apk_istream *is)
{
	return 0;
}

static const struct apk_extract_ops extract_v2verify_ops = {
	.v2index = apk_extract_verify_v2index,
	.v2meta = apk_extract_v2_meta,
	.file = apk_extract_verify_v2file,
};

static int apk_extract_v2_entry(void *pctx, const struct apk_file_info *fi, struct apk_istream *is)
{
	struct apk_extract_ctx *ectx = pctx;
	struct apk_sign_ctx *sctx = ectx->pctx;
	int r, type;

	r = apk_sign_ctx_process_file(sctx, fi, is);
	if (r <= 0) return r;

	if (!sctx->control_started) return 0;
	if (!sctx->data_started || !sctx->has_data_checksum) {
		if (fi->name[0] == '.') {
			ectx->is_package = 1;
			if (ectx->is_index) return -APKE_V2NDX_FORMAT;
			if (!ectx->ops->v2meta) return -APKE_FORMAT_NOT_SUPPORTED;
			if (strcmp(fi->name, ".PKGINFO") == 0) {
				return ectx->ops->v2meta(ectx, is);
			} else if (strcmp(fi->name, ".INSTALL") == 0) {
				return -APKE_V2PKG_FORMAT;
			} else if ((type = apk_script_type(&fi->name[1])) != APK_SCRIPT_INVALID) {
				if (ectx->ops->script) return ectx->ops->script(ectx, type, fi->size, is);
			}
		} else {
			ectx->is_index = 1;
			if (ectx->is_package) return -APKE_V2PKG_FORMAT;
			if (!ectx->ops->v2index) return -APKE_FORMAT_NOT_SUPPORTED;
			if (strcmp(fi->name, "DESCRIPTION") == 0) {
				free(ectx->desc.ptr);
				ectx->desc = apk_blob_from_istream(is, fi->size);
			} else if (strcmp(fi->name, "APKINDEX") == 0) {
				return ectx->ops->v2index(ectx, &ectx->desc, is);
			}
		}
		return 0;
	}

	if (!sctx->control_verified) return 0;
	if (!ectx->ops->file) return -ECANCELED;
	return ectx->ops->file(ectx, fi, is);
}

int apk_extract_v2(struct apk_extract_ctx *ectx, struct apk_istream *is)
{
	struct apk_ctx *ac = ectx->ac;
	struct apk_trust *trust = apk_ctx_get_trust(ac);
	struct apk_sign_ctx sctx;
	int r, action;

	if (ectx->generate_identity)
		action = trust->allow_untrusted ? APK_SIGN_GENERATE : APK_SIGN_VERIFY_AND_GENERATE;
	else if (ectx->identity)
		action = trust->allow_untrusted ? APK_SIGN_NONE : APK_SIGN_VERIFY_IDENTITY;
	else
		action = trust->allow_untrusted ? APK_SIGN_NONE : APK_SIGN_VERIFY;

	if (!ectx->ops) ectx->ops = &extract_v2verify_ops;
	ectx->pctx = &sctx;
	apk_sign_ctx_init(&sctx, action, ectx->identity, trust);
	r = apk_tar_parse(
		apk_istream_gunzip_mpart(is, apk_sign_ctx_mpart_cb, &sctx),
		apk_extract_v2_entry, ectx, apk_ctx_get_id_cache(ac));
	if (r == -ECANCELED) r = 0;
	if (r == 0 && !ectx->is_package && !ectx->is_index)
		r = ectx->ops->v2index ? -APKE_V2NDX_FORMAT : -APKE_V2PKG_FORMAT;
	if (ectx->generate_identity) *ectx->identity = sctx.identity;
	apk_sign_ctx_free(&sctx);
	free(ectx->desc.ptr);
	apk_extract_reset(ectx);

	return r;
}

void apk_extract_v2_control(struct apk_extract_ctx *ectx, apk_blob_t l, apk_blob_t r)
{
	struct apk_sign_ctx *sctx = ectx->pctx;

	if (!sctx || !sctx->control_started || sctx->data_started) return;

	if (apk_blob_compare(APK_BLOB_STR("datahash"), l) == 0) {
		sctx->has_data_checksum = 1;
		sctx->md = EVP_sha256();
		apk_blob_pull_hexdump(
			&r, APK_BLOB_PTR_LEN(sctx->data_checksum,
					EVP_MD_size(sctx->md)));
	}
}

int apk_extract_v2_meta(struct apk_extract_ctx *ectx, struct apk_istream *is)
{
	apk_blob_t k, v, token = APK_BLOB_STRLIT("\n");
	while (apk_istream_get_delim(is, token, &k) == 0) {
		if (k.len < 1 || k.ptr[0] == '#') continue;
		if (apk_blob_split(k, APK_BLOB_STRLIT(" = "), &k, &v)) {
			apk_extract_v2_control(ectx, k, v);
		}
	}
	return 0;
}

