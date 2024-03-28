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
#include "apk_version.h"
#include "apk_print.h"

/* TODO: support package files as well as generating manifest from the installed DB. */
static char *csum_types[APK_CHECKSUM_SHA1 + 1] = {
	/* Note: if adding new algorithms, update apk-manifest(8) */
	[APK_CHECKSUM_MD5] = "md5",
	[APK_CHECKSUM_SHA1] = "sha1",
};

struct manifest_file_ctx {
	const char *file;
	struct apk_sign_ctx *sctx;
};

static void process_package(struct apk_database *db, struct apk_package *pkg)
{
	struct apk_installed_package *ipkg = pkg->ipkg;
	struct apk_db_dir_instance *diri;
	struct apk_db_file *file;
	struct hlist_node *dc, *dn, *fc, *fn;
	char csum_buf[APK_BLOB_CHECKSUM_BUF];

	if (ipkg == NULL)
		return;

	hlist_for_each_entry_safe(diri, dc, dn, &ipkg->owned_dirs,
				  pkg_dirs_list) {
		hlist_for_each_entry_safe(file, fc, fn, &diri->owned_files,
					  diri_files_list) {
			apk_blob_t csum_blob = APK_BLOB_BUF(csum_buf);

			memset(csum_buf, '\0', sizeof(csum_buf));
			apk_blob_push_hexdump(&csum_blob, APK_BLOB_CSUM(file->csum));

			if (apk_verbosity > 1)
				printf("%s: ", pkg->name->name);

                        printf("%s:%s  " DIR_FILE_FMT "\n", csum_types[file->csum.type], csum_buf, DIR_FILE_PRINTF(diri->dir, file));
                }
	}
}

static int read_file_entry(void *ctx, const struct apk_file_info *ae,
                           struct apk_istream *is)
{
	struct manifest_file_ctx *mctx = ctx;
	char csum_buf[APK_BLOB_CHECKSUM_BUF];
	apk_blob_t csum_blob = APK_BLOB_BUF(csum_buf);
	int r;

	r = apk_sign_ctx_verify_tar(mctx->sctx, ae, is);
	if (r != 0)
		return r;

	if (!mctx->sctx->data_started)
		return 0;

	if ((ae->mode & S_IFMT) != S_IFREG)
		return 0;

	memset(csum_buf, '\0', sizeof(csum_buf));
	apk_blob_push_hexdump(&csum_blob, APK_BLOB_CSUM(ae->csum));

	if (apk_verbosity > 1)
		printf("%s: ", mctx->file);

	printf("%s:%s  %s\n", csum_types[ae->csum.type], csum_buf, ae->name);

	return 0;
}

static void process_file(struct apk_database *db, const char *match)
{
	struct apk_sign_ctx sctx;
	struct manifest_file_ctx ctx = {match, &sctx};
	int r;

	apk_sign_ctx_init(&sctx, APK_SIGN_VERIFY, NULL, db->keys_fd);
	r = apk_tar_parse(
		apk_istream_gunzip_mpart(apk_istream_from_file(AT_FDCWD, match), apk_sign_ctx_mpart_cb, &sctx),
		read_file_entry, &ctx, &db->id_cache);
	r = apk_sign_ctx_status(&sctx, r);
	apk_sign_ctx_free(&sctx);
	if (r < 0) apk_error("%s: %s", match, apk_error_str(r));
}

static int process_match(struct apk_database *db, const char *match, struct apk_name *name, void *ctx)
{
	struct apk_provider *p;

	if (!name) {
		process_file(db, match);
		return 0;
	}

	apk_name_sorted_providers(name);
	foreach_array_item(p, name->providers) {
		if (p->pkg->name != name) continue;
		process_package(db, p->pkg);
	}
	return 0;
}

static int manifest_main(void *ctx, struct apk_database *db, struct apk_string_array *args)
{
	if (!args->num) return 0;
	apk_db_foreach_sorted_name(db, args, process_match, NULL);
	return 0;
}

static struct apk_applet apk_manifest = {
	.name = "manifest",
	.open_flags = APK_OPENF_READ,
	.main = manifest_main,
};

APK_DEFINE_APPLET(apk_manifest);
