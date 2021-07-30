/* extract_v3.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <sys/stat.h>

#include "apk_context.h"
#include "apk_extract.h"
#include "apk_adb.h"
#include "apk_pathbuilder.h"

struct apk_extract_v3_ctx {
	struct apk_extract_ctx *ectx;
	struct adb db;
	struct adb_obj pkg, paths, path, files, file;
	unsigned int cur_path, cur_file;
	struct apk_pathbuilder pb;
};

static const char *uvol_detect(struct apk_ctx *ac, const char *path)
{
	if (!apk_ctx_get_uvol(ac)) return 0;
	if (strncmp(path, "uvol", 4) != 0) return 0;
	if (path[4] == 0) return path;
	if (path[4] == '/') return &path[5];
	return 0;
}

static void apk_extract_v3_acl(struct apk_file_info *fi, struct adb_obj *o, struct apk_id_cache *idc)
{
	fi->mode = adb_ro_int(o, ADBI_ACL_MODE);
	fi->uid = apk_id_cache_resolve_uid(idc, adb_ro_blob(o, ADBI_ACL_USER), 65534);
	fi->gid = apk_id_cache_resolve_gid(idc, adb_ro_blob(o, ADBI_ACL_GROUP), 65534);
}

static int apk_extract_v3_file(struct apk_extract_ctx *ectx, off_t sz, struct apk_istream *is)
{
	struct apk_extract_v3_ctx *ctx = ectx->pctx;
	struct apk_ctx *ac = ectx->ac;
	const char *path_name = apk_pathbuilder_cstr(&ctx->pb);
	struct apk_file_info fi = {
		.name = path_name,
		.uvol_name = uvol_detect(ac, path_name),
		.size = adb_ro_int(&ctx->file, ADBI_FI_SIZE),
		.mtime = adb_ro_int(&ctx->file, ADBI_FI_MTIME),
	};
	struct adb_obj acl;
	struct apk_digest_istream dis;
	apk_blob_t target;
	int r;

	apk_extract_v3_acl(&fi, adb_ro_obj(&ctx->file, ADBI_FI_ACL, &acl), apk_ctx_get_id_cache(ectx->ac));

	target = adb_ro_blob(&ctx->file, ADBI_FI_TARGET);
	if (!APK_BLOB_IS_NULL(target)) {
		char *target_path;
		uint16_t mode;

		if (target.len < 2) return -APKE_ADB_SCHEMA;
		mode = *(uint16_t*)target.ptr;
		target.ptr += 2;
		target.len -= 2;
		switch (mode) {
		case S_IFBLK:
		case S_IFCHR:
		case S_IFIFO:
			if (target.len != sizeof(uint64_t)) return -APKE_ADB_SCHEMA;
			struct unaligned64 {
				uint64_t value;
			} __attribute__((packed));
			fi.device = ((struct unaligned64 *)target.ptr)->value;
			break;
		case S_IFLNK:
			target_path = alloca(target.len + 1);
			memcpy(target_path, target.ptr, target.len);
			target_path[target.len] = 0;
			fi.link_target = target_path;
			break;
		default:
			return -APKE_ADB_SCHEMA;
		}
		fi.mode |= mode;
		return ectx->ops->file(ectx, &fi, is);
	}

	apk_digest_from_blob(&fi.digest, adb_ro_blob(&ctx->file, ADBI_FI_HASHES));
	if (fi.digest.alg == APK_DIGEST_NONE) return -APKE_ADB_SCHEMA;

	fi.mode |= S_IFREG;
	r = ectx->ops->file(ectx, &fi, apk_istream_verify(&dis, is, &fi.digest));
	return apk_istream_close_error(&dis.is, r);
}

static int apk_extract_v3_directory(struct apk_extract_ctx *ectx)
{
	struct apk_extract_v3_ctx *ctx = ectx->pctx;
	struct apk_ctx *ac = ectx->ac;
	struct apk_file_info fi = {
		.name = apk_pathbuilder_cstr(&ctx->pb),
	};
	struct adb_obj acl;

	if (uvol_detect(ac, fi.name)) return 0;

	apk_extract_v3_acl(&fi, adb_ro_obj(&ctx->path, ADBI_DI_ACL, &acl), apk_ctx_get_id_cache(ectx->ac));
	fi.mode |= S_IFDIR;

	return ectx->ops->file(ectx, &fi, 0);
}

static int apk_extract_v3_next_file(struct apk_extract_ctx *ectx)
{
	struct apk_extract_v3_ctx *ctx = ectx->pctx;
	apk_blob_t target;
	int r;

	if (!ctx->cur_path) {
		r = ectx->ops->v3meta(ectx, &ctx->db);
		if (r < 0) return r;

		// one time init
		ctx->cur_path = ADBI_FIRST;
		ctx->cur_file = 0;
		adb_r_rootobj(&ctx->db, &ctx->pkg, &schema_package);
		adb_ro_obj(&ctx->pkg, ADBI_PKG_PATHS, &ctx->paths);
		adb_ro_obj(&ctx->paths, ctx->cur_path, &ctx->path);
		adb_ro_obj(&ctx->path, ADBI_DI_FILES, &ctx->files);
		if (!ectx->ops->file) return -ECANCELED;
	}

	do {
		ctx->cur_file++;
		while (ctx->cur_file > adb_ra_num(&ctx->files)) {
			ctx->cur_path++;
			ctx->cur_file = ADBI_FIRST;
			if (ctx->cur_path > adb_ra_num(&ctx->paths)) return 1;
			adb_ro_obj(&ctx->paths, ctx->cur_path, &ctx->path);
			apk_pathbuilder_setb(&ctx->pb, adb_ro_blob(&ctx->path, ADBI_DI_NAME));
			adb_ro_obj(&ctx->path, ADBI_DI_FILES, &ctx->files);
			r = apk_extract_v3_directory(ectx);
			if (r != 0) return r;
		}
		adb_ro_obj(&ctx->files, ctx->cur_file, &ctx->file);
		apk_pathbuilder_setb(&ctx->pb, adb_ro_blob(&ctx->path, ADBI_DI_NAME));
		apk_pathbuilder_pushb(&ctx->pb, adb_ro_blob(&ctx->file, ADBI_FI_NAME));
		target = adb_ro_blob(&ctx->file, ADBI_FI_TARGET);
		if (adb_ro_int(&ctx->file, ADBI_FI_SIZE) != 0 &&
		    APK_BLOB_IS_NULL(target)) {
			return 0;
		}
		r = apk_extract_v3_file(ectx, 0, 0);
		if (r != 0) return r;
	} while (1);
}

static int apk_extract_v3_data_block(struct adb *db, struct adb_block *b, struct apk_istream *is)
{
	struct apk_extract_v3_ctx *ctx = container_of(db, struct apk_extract_v3_ctx, db);
	struct apk_extract_ctx *ectx = ctx->ectx;
	struct adb_data_package *hdr;
	size_t sz = adb_block_length(b);
	int r;

	if (adb_block_type(b) != ADB_BLOCK_DATA) return 0;

	r = apk_extract_v3_next_file(ectx);
	if (r != 0) {
		if (r > 0) r = -APKE_ADB_BLOCK;
		return r;
	}

	hdr = apk_istream_get(is, sizeof *hdr);
	sz -= sizeof *hdr;
	if (IS_ERR(hdr)) return PTR_ERR(hdr);

	if (hdr->path_idx != ctx->cur_path ||
	    hdr->file_idx != ctx->cur_file ||
	    sz != adb_ro_int(&ctx->file, ADBI_FI_SIZE)) {
		// got data for some unexpected file
		return -APKE_ADB_BLOCK;
	}

	return apk_extract_v3_file(ectx, sz, is);
}

int apk_extract_v3(struct apk_extract_ctx *ectx, struct apk_istream *is)
{
	struct apk_ctx *ac = ectx->ac;
	struct apk_trust *trust = apk_ctx_get_trust(ac);
	struct apk_extract_v3_ctx ctx = {
		.ectx = ectx,
	};
	int r;

	if (IS_ERR(is)) return PTR_ERR(is);
	if (!ectx->ops || !ectx->ops->v3meta)
		return apk_istream_close_error(is, -APKE_FORMAT_NOT_SUPPORTED);

	ectx->pctx = &ctx;
	r = adb_m_process(&ctx.db, adb_decompress(is, 0),
		ADB_SCHEMA_PACKAGE, trust, apk_extract_v3_data_block);
	if (r == 0) {
		r = apk_extract_v3_next_file(ectx);
		if (r == 0) r = -APKE_ADB_BLOCK;
		if (r == 1) r = 0;
	}
	if (r == -ECANCELED) r = 0;
	adb_free(&ctx.db);
	ectx->pctx = 0;
	return r;
}
