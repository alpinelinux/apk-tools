/* app_mkpkg.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2008-2021 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

#include "apk_defines.h"
#include "apk_adb.h"
#include "apk_applet.h"
#include "apk_database.h"
#include "apk_pathbuilder.h"
#include "apk_extract.h"
#include "apk_print.h"

#define BLOCK_SIZE 4096

struct mkpkg_ctx {
	struct apk_ctx *ac;
	const char *files_dir, *output;
	struct adb db;
	struct adb_obj paths, *files;
	struct apk_extract_ctx ectx;
	apk_blob_t package[ADBI_PKG_MAX];
	apk_blob_t info[ADBI_PI_MAX];
	apk_blob_t script[ADBI_SCRPT_MAX];
	struct apk_string_array *triggers;
	uint64_t installed_size;
	struct apk_pathbuilder pb;
	unsigned has_scripts : 1;
};

#define MKPKG_OPTIONS(OPT) \
	OPT(OPT_MKPKG_files,	APK_OPT_ARG APK_OPT_SH("f") "files") \
	OPT(OPT_MKPKG_info,	APK_OPT_ARG APK_OPT_SH("I") "info") \
	OPT(OPT_MKPKG_output,	APK_OPT_ARG APK_OPT_SH("o") "output") \
	OPT(OPT_MKPKG_script,	APK_OPT_ARG APK_OPT_SH("s") "script") \
	OPT(OPT_MKPKG_trigger,	APK_OPT_ARG APK_OPT_SH("t") "trigger") \

APK_OPT_APPLET(option_desc, MKPKG_OPTIONS);

static int parse_info(struct mkpkg_ctx *ictx, struct apk_out *out, const char *optarg)
{
	apk_blob_t l, r;
	int i;

	if (!apk_blob_split(APK_BLOB_STR(optarg), APK_BLOB_STRLIT(":"), &l, &r))
		goto inval;

	i = adb_s_field_by_name_blob(&schema_pkginfo, l);
	switch (i) {
	case 0:
		break;
	case ADBI_PI_FILE_SIZE:
	case ADBI_PI_INSTALLED_SIZE:
		return -EINVAL;
	default:
		ictx->info[i] = r;
		return 0;
	}

	i = adb_s_field_by_name_blob(&schema_package, l);
	switch (i) {
#if 0
	case ADBI_PKG_xxx:
		ictx->package[i] = r;
		break;
#endif
	default:
		break;
	}

inval:
	apk_err(out, "invalid info field: " BLOB_FMT, BLOB_PRINTF(l));
	return -EINVAL;
}

static int option_parse_applet(void *ctx, struct apk_ctx *ac, int optch, const char *optarg)
{
	struct apk_out *out = &ac->out;
	struct mkpkg_ctx *ictx = ctx;
	apk_blob_t l, r;
	int i;

	switch (optch) {
	case OPT_MKPKG_info:
		return parse_info(ictx, out, optarg);
	case OPT_MKPKG_files:
		ictx->files_dir = optarg;
		break;
	case OPT_MKPKG_output:
		ictx->output = optarg;
		break;
	case OPT_MKPKG_script:
		apk_blob_split(APK_BLOB_STR(optarg), APK_BLOB_STRLIT(":"), &l, &r);
		i = adb_s_field_by_name_blob(&schema_scripts, l);
		if (!i) {
			apk_err(out, "invalid script type: " BLOB_FMT, BLOB_PRINTF(l));
			return -EINVAL;
		}
		ictx->script[i] = apk_blob_from_file(AT_FDCWD, r.ptr);
		if (APK_BLOB_IS_NULL(ictx->script[i])) {
			apk_err(out, "failed to load script: " BLOB_FMT, BLOB_PRINTF(r));
			return -ENOENT;
		}
		ictx->has_scripts = 1;
		break;
	case OPT_MKPKG_trigger:
		*apk_string_array_add(&ictx->triggers) = (char*) optarg;
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

static const struct apk_option_group optgroup_applet = {
	.desc = option_desc,
	.parse = option_parse_applet,
};

static int mkpkg_process_dirent(void *pctx, int dirfd, const char *entry);

static int mkpkg_process_directory(struct mkpkg_ctx *ctx, int dirfd, struct apk_file_info *fi)
{
	struct apk_ctx *ac = ctx->ac;
	struct apk_id_cache *idc = apk_ctx_get_id_cache(ac);
	struct apk_out *out = &ac->out;
	struct adb_obj acl, fio, files, *prev_files;
	apk_blob_t dirname = apk_pathbuilder_get(&ctx->pb);
	int r;

	adb_wo_alloca(&fio, &schema_dir, &ctx->db);
	adb_wo_alloca(&acl, &schema_acl, &ctx->db);
	adb_wo_blob(&fio, ADBI_DI_NAME, dirname);
	adb_wo_int(&acl, ADBI_ACL_MODE, fi->mode & ~S_IFMT);
	adb_wo_blob(&acl, ADBI_ACL_USER, apk_id_cache_resolve_user(idc, fi->uid));
	adb_wo_blob(&acl, ADBI_ACL_GROUP, apk_id_cache_resolve_group(idc, fi->gid));
	adb_wo_obj(&fio, ADBI_DI_ACL, &acl);

	adb_wo_alloca(&files, &schema_file_array, &ctx->db);
	prev_files = ctx->files;
	ctx->files = &files;
	r = apk_dir_foreach_file(dirfd, mkpkg_process_dirent, ctx);
	ctx->files = prev_files;
	if (r) {
		apk_err(out, "failed to process directory '%s': %d",
			apk_pathbuilder_cstr(&ctx->pb), r);
		return r;
	}

	adb_wo_obj(&fio, ADBI_DI_FILES, &files);
	adb_wa_append_obj(&ctx->paths, &fio);
	return 0;
}

static int mkpkg_process_dirent(void *pctx, int dirfd, const char *entry)
{
	struct mkpkg_ctx *ctx = pctx;
	struct apk_ctx *ac = ctx->ac;
	struct apk_out *out = &ac->out;
	struct apk_id_cache *idc = apk_ctx_get_id_cache(ac);
	struct apk_file_info fi;
	struct adb_obj fio, acl;
	apk_blob_t target = APK_BLOB_NULL;
	union {
		uint16_t mode;
		struct {
			uint16_t mode;
			uint64_t dev;
		} __attribute__((packed)) dev;
		struct {
			uint16_t mode;
			char target[1022];
		} symlink;
	} ft;
	int r, n;

	r = apk_fileinfo_get(dirfd, entry, APK_FI_NOFOLLOW | APK_FI_DIGEST(APK_DIGEST_SHA256), &fi, NULL);
	if (r) return r;

	switch (fi.mode & S_IFMT) {
	case S_IFREG:
		ctx->installed_size += (fi.size + BLOCK_SIZE - 1) & ~(BLOCK_SIZE-1);
		break;
	case S_IFBLK:
	case S_IFCHR:
	case S_IFIFO:
		ft.dev.mode = fi.mode & S_IFMT;
		ft.dev.dev = fi.device;
		target = APK_BLOB_STRUCT(ft.dev);
		break;
	case S_IFLNK:
		ft.symlink.mode = fi.mode & S_IFMT;
		r = readlinkat(dirfd, entry, ft.symlink.target, sizeof ft.symlink.target);
		if (r < 0) return r;
		target = APK_BLOB_PTR_LEN((void*)&ft.symlink, sizeof(ft.symlink.mode) + r);
		r = 0;
		break;
	case S_IFDIR:
		n = apk_pathbuilder_push(&ctx->pb, entry);
		r = mkpkg_process_directory(ctx, openat(dirfd, entry, O_RDONLY), &fi);
		apk_pathbuilder_pop(&ctx->pb, n);
		return r;
	default:
		n = apk_pathbuilder_push(&ctx->pb, entry);
		apk_out(out, "%s: special file ignored", apk_pathbuilder_cstr(&ctx->pb));
		apk_pathbuilder_pop(&ctx->pb, n);
		return 0;
	}

	adb_wo_alloca(&fio, &schema_file, &ctx->db);
	adb_wo_alloca(&acl, &schema_acl, &ctx->db);
	adb_wo_blob(&fio, ADBI_FI_NAME, APK_BLOB_STR(entry));
	if (APK_BLOB_IS_NULL(target))
		adb_wo_blob(&fio, ADBI_FI_HASHES, APK_DIGEST_BLOB(fi.digest));
	else
		adb_wo_blob(&fio, ADBI_FI_TARGET, target);
	adb_wo_int(&fio, ADBI_FI_MTIME, fi.mtime);
	adb_wo_int(&fio, ADBI_FI_SIZE, fi.size);

	adb_wo_int(&acl, ADBI_ACL_MODE, fi.mode & 07777);
	adb_wo_blob(&acl, ADBI_ACL_USER, apk_id_cache_resolve_user(idc, fi.uid));
	adb_wo_blob(&acl, ADBI_ACL_GROUP, apk_id_cache_resolve_group(idc, fi.gid));
	adb_wo_obj(&fio, ADBI_FI_ACL, &acl);

	adb_wa_append_obj(ctx->files, &fio);

	return r;
}

static char *pkgi_filename(struct adb_obj *pkgi, char *buf, size_t n)
{
	apk_blob_t to = APK_BLOB_PTR_LEN(buf, n);
	apk_blob_push_blob(&to, adb_ro_blob(pkgi, ADBI_PI_NAME));
	apk_blob_push_blob(&to, APK_BLOB_STR("-"));
	apk_blob_push_blob(&to, adb_ro_blob(pkgi, ADBI_PI_VERSION));
	apk_blob_push_blob(&to, APK_BLOB_STR(".apk"));
	apk_blob_push_blob(&to, APK_BLOB_PTR_LEN("", 1));
	if (APK_BLOB_IS_NULL(to)) return 0;
	return buf;
}

static int check_required(struct apk_out *out, apk_blob_t *vals, int index, const struct adb_object_schema *schema)
{
	if (!APK_BLOB_IS_NULL(vals[index])) return 0;
	apk_err(out, "required info field '%s' not provided",
		schema->fields[index-1].name);
	return -EINVAL;
}

static int assign_fields(struct apk_out *out, apk_blob_t *vals, int num_vals, struct adb_obj *obj)
{
	int i, r;

	for (i = 0; i < num_vals; i++) {
		apk_blob_t b = vals[i];
		if (APK_BLOB_IS_NULL(b)) continue;

		adb_val_t val = adb_wo_val_fromstring(obj, i, b);
		if (ADB_IS_ERROR(val)) {
			r = ADB_VAL_VALUE(val);
			apk_err(out, "info field '%s' has invalid value: %s",
				obj->schema->fields[i-1].name, apk_error_str(r));
			return r;
		}
	}
	return 0;
}

static int mkpkg_main(void *pctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	struct apk_out *out = &ac->out;
	struct apk_trust *trust = apk_ctx_get_trust(ac);
	struct adb_obj pkg, pkgi;
	int i, j, r;
	struct mkpkg_ctx *ctx = pctx;
	struct apk_ostream *os;
	struct apk_digest d = {};
	char outbuf[PATH_MAX];
	const int uid_len = apk_digest_alg_len(APK_DIGEST_SHA1);
	apk_blob_t uid = APK_BLOB_PTR_LEN((char*)d.data, uid_len);

	ctx->ac = ac;
	adb_w_init_alloca(&ctx->db, ADB_SCHEMA_PACKAGE, 40);
	adb_wo_alloca(&pkg, &schema_package, &ctx->db);
	adb_wo_alloca(&pkgi, &schema_pkginfo, &ctx->db);
	adb_wo_alloca(&ctx->paths, &schema_dir_array, &ctx->db);

	// prepare package info
	r = -EINVAL;
	if (check_required(out, ctx->info, ADBI_PI_NAME, &schema_pkginfo) ||
	    check_required(out, ctx->info, ADBI_PI_VERSION, &schema_pkginfo))
		goto err;

	if (APK_BLOB_IS_NULL(ctx->info[ADBI_PI_ARCH]))
		ctx->info[ADBI_PI_ARCH] = APK_BLOB_STRLIT(APK_DEFAULT_ARCH);

	r = assign_fields(out, ctx->info, ARRAY_SIZE(ctx->info), &pkgi);
	if (r) goto err;

	r = assign_fields(out, ctx->package, ARRAY_SIZE(ctx->package), &pkg);
	if (r) goto err;

	// scan and add all files
	if (ctx->files_dir) {
		struct apk_file_info fi;
		r = apk_fileinfo_get(AT_FDCWD, ctx->files_dir, APK_FI_NOFOLLOW, &fi, 0);
		if (r) {
			apk_err(out, "file directory '%s': %s",
				ctx->files_dir, apk_error_str(r));
			goto err;
		}
		r = mkpkg_process_directory(ctx, openat(AT_FDCWD, ctx->files_dir, O_RDONLY), &fi);
		if (r) goto err;
		if (!ctx->installed_size) ctx->installed_size = BLOCK_SIZE;
	}

	adb_wo_int(&pkgi, ADBI_PI_INSTALLED_SIZE, ctx->installed_size);
	adb_wo_blob(&pkgi, ADBI_PI_UNIQUE_ID, uid);

	adb_wo_obj(&pkg, ADBI_PKG_PKGINFO, &pkgi);
	adb_wo_obj(&pkg, ADBI_PKG_PATHS, &ctx->paths);
	if (ctx->has_scripts) {
		struct adb_obj scripts;
		adb_wo_alloca(&scripts, &schema_scripts, &ctx->db);
		for (i = ADBI_FIRST; i < ADBI_SCRPT_MAX; i++)
			adb_wo_blob(&scripts, i, ctx->script[i]);
		adb_wo_obj(&pkg, ADBI_PKG_SCRIPTS, &scripts);
	}
	if (ctx->triggers) {
		struct adb_obj triggers;
		adb_wo_alloca(&triggers, &schema_string_array, &ctx->db);
		for (i = 0; i < ctx->triggers->num; i++)
			adb_wa_append_fromstring(&triggers, APK_BLOB_STR(ctx->triggers->item[i]));
		adb_wo_obj(&pkg, ADBI_PKG_TRIGGERS, &triggers);
	}
	adb_w_rootobj(&pkg);

	// re-read since object resets
	adb_r_rootobj(&ctx->db, &pkg, &schema_package);
	adb_ro_obj(&pkg, ADBI_PKG_PKGINFO, &pkgi);
	adb_ro_obj(&pkg, ADBI_PKG_PATHS, &ctx->paths);

	// fill in unique id
	apk_digest_calc(&d, APK_DIGEST_SHA256, ctx->db.adb.ptr, ctx->db.adb.len);
	uid = adb_ro_blob(&pkgi, ADBI_PI_UNIQUE_ID);
	memcpy(uid.ptr, d.data, uid.len);

	if (!ctx->output) {
		ctx->output = pkgi_filename(&pkgi, outbuf, sizeof outbuf);
	}

	// construct package with ADB as header, and the file data in
	// concatenated data blocks
	os = adb_compress(apk_ostream_to_file(AT_FDCWD, ctx->output, 0644), ADB_COMP_DEFLATE);
	if (IS_ERR(os)) {
		r = PTR_ERR(os);
		goto err;
	}

	adb_c_adb(os, &ctx->db, trust);
	int files_fd = openat(AT_FDCWD, ctx->files_dir, O_RDONLY);
	for (i = ADBI_FIRST; i <= adb_ra_num(&ctx->paths); i++) {
		struct adb_obj path, files, file;
		adb_ro_obj(&ctx->paths, i, &path);
		adb_ro_obj(&path, ADBI_DI_FILES, &files);
		apk_blob_t dirname = adb_ro_blob(&path, ADBI_DI_NAME);

		apk_pathbuilder_setb(&ctx->pb, dirname);
		for (j = ADBI_FIRST; j <= adb_ra_num(&files); j++) {
			adb_ro_obj(&files, j, &file);
			apk_blob_t filename = adb_ro_blob(&file, ADBI_FI_NAME);
			apk_blob_t target = adb_ro_blob(&file, ADBI_FI_TARGET);
			size_t sz = adb_ro_int(&file, ADBI_FI_SIZE);
			if (!APK_BLOB_IS_NULL(target)) continue;
			if (!sz) continue;
			struct adb_data_package hdr = {
				.path_idx = i,
				.file_idx = j,
			};
			int n = apk_pathbuilder_pushb(&ctx->pb, filename);
			adb_c_block_data(
				os, APK_BLOB_STRUCT(hdr), sz,
				apk_istream_from_fd(openat(files_fd,
					apk_pathbuilder_cstr(&ctx->pb),
					O_RDONLY)));
			apk_pathbuilder_pop(&ctx->pb, n);
		}
	}
	close(files_fd);
	r = apk_ostream_close(os);

err:
	adb_free(&ctx->db);
	if (r) apk_err(out, "failed to create package: %s: %s", ctx->output, apk_error_str(r));
	return r;
}

static struct apk_applet apk_mkpkg = {
	.name = "mkpkg",
	.context_size = sizeof(struct mkpkg_ctx),
	.optgroups = { &optgroup_global, &optgroup_signing, &optgroup_applet },
	.main = mkpkg_main,
};

APK_DEFINE_APPLET(apk_mkpkg);
