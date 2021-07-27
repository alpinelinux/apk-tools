/* app_manifest.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2017 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2017 Timo Teräs <timo.teras@iki.fi>
 * Copyright (C) 2017 William Pitcock <nenolod@dereferenced.org>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include <sys/stat.h>

#include "apk_defines.h"
#include "apk_applet.h"
#include "apk_database.h"
#include "apk_extract.h"
#include "apk_version.h"
#include "apk_print.h"

/* TODO: support package files as well as generating manifest from the installed DB. */
static char *csum_types[APK_CHECKSUM_SHA1 + 1] = {
	/* Note: if adding new algorithms, update apk-manifest(8) */
	[APK_CHECKSUM_MD5] = "md5",
	[APK_CHECKSUM_SHA1] = "sha1",
};

static void process_package(struct apk_database *db, struct apk_package *pkg)
{
	struct apk_out *out = &db->ctx->out;
	struct apk_installed_package *ipkg = pkg->ipkg;
	struct apk_db_dir_instance *diri;
	struct apk_db_file *file;
	struct hlist_node *dc, *dn, *fc, *fn;
	const char *prefix1 = "", *prefix2 = "";
	char csum_buf[APK_BLOB_CHECKSUM_BUF];

	if (ipkg == NULL)
		return;

	if (apk_out_verbosity(out) > 1) {
		prefix1 = pkg->name->name;
		prefix2 = ": ";
	}

	hlist_for_each_entry_safe(diri, dc, dn, &ipkg->owned_dirs,
				  pkg_dirs_list) {
		hlist_for_each_entry_safe(file, fc, fn, &diri->owned_files,
					  diri_files_list) {
			apk_blob_t csum_blob = APK_BLOB_BUF(csum_buf);
			memset(csum_buf, '\0', sizeof(csum_buf));
			apk_blob_push_hexdump(&csum_blob, APK_BLOB_CSUM(file->csum));

			apk_out(out, "%s%s%s:%s  " DIR_FILE_FMT,
				prefix1, prefix2,
				csum_types[file->csum.type], csum_buf,
				DIR_FILE_PRINTF(diri->dir, file));
		}
	}
}

struct manifest_file_ctx {
	struct apk_out *out;
	struct apk_extract_ctx ectx;
	const char *prefix1, *prefix2;
};

static int process_pkg_file(struct apk_extract_ctx *ectx, const struct apk_file_info *fi, struct apk_istream *is)
{
	struct manifest_file_ctx *mctx = container_of(ectx, struct manifest_file_ctx, ectx);
	struct apk_out *out = mctx->out;
	char csum_buf[APK_BLOB_CHECKSUM_BUF];
	apk_blob_t csum_blob = APK_BLOB_BUF(csum_buf);

	if ((fi->mode & S_IFMT) != S_IFREG) return 0;

	memset(csum_buf, '\0', sizeof(csum_buf));
	apk_blob_push_hexdump(&csum_blob, APK_DIGEST_BLOB(fi->digest));

	apk_out(out, "%s%s%s:%s  %s",
		mctx->prefix1, mctx->prefix2,
		apk_digest_alg_str(fi->digest.alg), csum_buf,
		fi->name);

	return 0;
}

static const struct apk_extract_ops extract_manifest_ops = {
	.v2meta = apk_extract_v2_meta,
	.file = process_pkg_file,
};

static void process_file(struct apk_database *db, const char *match)
{
	struct apk_out *out = &db->ctx->out;
	struct manifest_file_ctx ctx = {
		.out = out,
		.prefix1 = "",
		.prefix2 = "",
	};
	int r;

	apk_extract_init(&ctx.ectx, db->ctx, &extract_manifest_ops);
	if (apk_out_verbosity(out) > 1) {
		ctx.prefix1 = match;
		ctx.prefix2 = ": ";
	}

	r = apk_extract(&ctx.ectx, apk_istream_from_file(AT_FDCWD, match));
	if (r < 0) apk_err(out, "%s: %s", match, apk_error_str(r));
}

static void process_match(struct apk_database *db, const char *match, struct apk_name *name, void *ctx)
{
	struct apk_provider *p;

	if (name == NULL) {
		process_file(db, match);
		return;
	}

	foreach_array_item(p, name->providers)
		process_package(db, p->pkg);
}

static int manifest_main(void *applet_ctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	apk_name_foreach_matching(ac->db, args, apk_foreach_genid(), process_match, NULL);
	return 0;
}

static struct apk_applet apk_manifest = {
	.name = "manifest",
	.open_flags = APK_OPENF_READ,
	.main = manifest_main,
};

APK_DEFINE_APPLET(apk_manifest);
