/* app_mkndx.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2020 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "apk_adb.h"
#include "apk_applet.h"
#include "apk_database.h"
#include "apk_extract.h"
#include "apk_print.h"

struct mkndx_ctx {
	const char *index;
	const char *output;
	const char *description;
	apk_blob_t rewrite_arch;

	apk_blob_t r;
	struct adb db;
	struct adb_obj pkgs;
	struct adb_obj pkginfo;
	time_t index_mtime;
	uint8_t hash_alg;

	struct apk_extract_ctx ectx;
	size_t file_size;
};

#define ALLOWED_HASH (BIT(APK_DIGEST_SHA256)|BIT(APK_DIGEST_SHA256_160))

#define MKNDX_OPTIONS(OPT) \
	OPT(OPT_MKNDX_description,	APK_OPT_ARG APK_OPT_SH("d") "description") \
	OPT(OPT_MKNDX_hash,		APK_OPT_ARG "hash") \
	OPT(OPT_MKNDX_index,		APK_OPT_ARG APK_OPT_SH("x") "index") \
	OPT(OPT_MKNDX_output,		APK_OPT_ARG APK_OPT_SH("o") "output") \
	OPT(OPT_MKNDX_rewrite_arch,	APK_OPT_ARG "rewrite-arch")

APK_OPT_APPLET(option_desc, MKNDX_OPTIONS);

static int option_parse_applet(void *ctx, struct apk_ctx *ac, int optch, const char *optarg)
{
	struct mkndx_ctx *ictx = ctx;
	struct apk_out *out = &ac->out;

	switch (optch) {
	case APK_OPTIONS_INIT:
		ictx->hash_alg = APK_DIGEST_SHA256;
		break;
	case OPT_MKNDX_description:
		ictx->description = optarg;
		break;
	case OPT_MKNDX_hash:
		ictx->hash_alg = apk_digest_alg_by_str(optarg);
		if (!(BIT(ictx->hash_alg) & ALLOWED_HASH)) {
			apk_err(out, "hash '%s' not recognized or allowed", optarg);
			return -EINVAL;
		}
		break;
	case OPT_MKNDX_index:
		ictx->index = optarg;
		break;
	case OPT_MKNDX_output:
		ictx->output = optarg;
		break;
	case OPT_MKNDX_rewrite_arch:
		ictx->rewrite_arch = APK_BLOB_STR(optarg);
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

struct field {
	apk_blob_t str;
	unsigned int ndx;
};
#define FIELD(s, n) { .str = APK_BLOB_STRLIT(s), .ndx = n }

static int cmpfield(const void *pa, const void *pb)
{
	const struct field *a = pa, *b = pb;
	return apk_blob_sort(a->str, b->str);
}

static int mkndx_parse_v2meta(struct apk_extract_ctx *ectx, struct apk_istream *is)
{
	static struct field fields[]  = {
		FIELD("arch",			ADBI_PI_ARCH),
		FIELD("builddate",		ADBI_PI_BUILD_TIME),
		FIELD("commit",			ADBI_PI_REPO_COMMIT),
		FIELD("datahash",		0),
		FIELD("depend",			ADBI_PI_DEPENDS),
		FIELD("install_if",		ADBI_PI_INSTALL_IF),
		FIELD("license",		ADBI_PI_LICENSE),
		FIELD("maintainer",		ADBI_PI_MAINTAINER),
		FIELD("origin",			ADBI_PI_ORIGIN),
		FIELD("packager",		0),
		FIELD("pkgdesc",		ADBI_PI_DESCRIPTION),
		FIELD("pkgname",		ADBI_PI_NAME),
		FIELD("pkgver", 		ADBI_PI_VERSION),
		FIELD("provider_priority",	ADBI_PI_PROVIDER_PRIORITY),
		FIELD("provides",		ADBI_PI_PROVIDES),
		FIELD("replaces",		ADBI_PI_REPLACES),
		FIELD("replaces_priority",	0),
		FIELD("size",			ADBI_PI_INSTALLED_SIZE),
		FIELD("triggers",		0),
		FIELD("url",			ADBI_PI_URL),
	};
	struct mkndx_ctx *ctx = container_of(ectx, struct mkndx_ctx, ectx);
	struct field *f, key;
	struct adb *db = &ctx->db;
	struct adb_obj deps[3];
	apk_blob_t line, k, v, token = APK_BLOB_STR("\n"), bdep;
	int r, e = 0, i = 0;

	adb_wo_alloca(&deps[0], &schema_dependency_array, db);
	adb_wo_alloca(&deps[1], &schema_dependency_array, db);
	adb_wo_alloca(&deps[2], &schema_dependency_array, db);

	while ((r = apk_istream_get_delim(is, token, &line)) == 0) {
		if (line.len < 1 || line.ptr[0] == '#') continue;
		if (!apk_blob_split(line, APK_BLOB_STR(" = "), &k, &v)) continue;
		apk_extract_v2_control(ectx, k, v);

		key.str = k;
		f = bsearch(&key, fields, ARRAY_SIZE(fields), sizeof(fields[0]), cmpfield);
		if (!f || f->ndx == 0) continue;

		if (adb_ro_val(&ctx->pkginfo, f->ndx) != ADB_NULL) {
			/* Workaround abuild bug that emitted multiple license lines */
			if (f->ndx == ADBI_PI_LICENSE) continue;
			return ADB_ERROR(APKE_ADB_PACKAGE_FORMAT);
		}

		switch (f->ndx) {
		case ADBI_PI_ARCH:
			if (!APK_BLOB_IS_NULL(ctx->rewrite_arch)) v = ctx->rewrite_arch;
			break;
		case ADBI_PI_DEPENDS:
			i = 0;
			goto parse_deps;
		case ADBI_PI_PROVIDES:
			i = 1;
			goto parse_deps;
		case ADBI_PI_REPLACES:
			i = 2;
		parse_deps:
			while (apk_dep_split(&v, &bdep)) {
				e = adb_wa_append_fromstring(&deps[i], bdep);
				if (ADB_IS_ERROR(e)) return e;
			}
			continue;
		}
		adb_wo_pkginfo(&ctx->pkginfo, f->ndx, v);
	}
	if (r != -APKE_EOF) return ADB_ERROR(-r);

	adb_wo_arr(&ctx->pkginfo, ADBI_PI_DEPENDS, &deps[0]);
	adb_wo_arr(&ctx->pkginfo, ADBI_PI_PROVIDES, &deps[1]);
	adb_wo_arr(&ctx->pkginfo, ADBI_PI_REPLACES, &deps[2]);

	return 0;
}

static int mkndx_parse_v3meta(struct apk_extract_ctx *ectx, struct adb_obj *pkg)
{
	struct mkndx_ctx *ctx = container_of(ectx, struct mkndx_ctx, ectx);
	struct adb_obj pkginfo;

	adb_ro_obj(pkg, ADBI_PKG_PKGINFO, &pkginfo);
	adb_wo_copyobj(&ctx->pkginfo, &pkginfo);

	return 0;
}

static const struct apk_extract_ops extract_ndxinfo_ops = {
	.v2meta = mkndx_parse_v2meta,
	.v3meta = mkndx_parse_v3meta,
};

static int mkndx_main(void *pctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	struct apk_out *out = &ac->out;
	struct apk_trust *trust = apk_ctx_get_trust(ac);
	struct adb odb, tmpdb;
	struct adb_obj oroot, opkgs, ndx, tmpl;
	struct apk_file_info fi;
	struct apk_digest digest;
	adb_val_t val;
	int r, found, errors = 0, newpkgs = 0, numpkgs;
	struct mkndx_ctx *ctx = pctx;
	char **parg;
	time_t index_mtime = 0;

	if (ctx->output == NULL) {
		apk_err(out, "Please specify --output FILE");
		return -1;
	}

	apk_extract_init(&ctx->ectx, ac, &extract_ndxinfo_ops);

	adb_init(&odb);
	adb_w_init_tmp(&tmpdb, 200);
	adb_wo_alloca(&tmpl, &schema_pkginfo, &tmpdb);

	adb_w_init_alloca(&ctx->db, ADB_SCHEMA_INDEX, 8000);
	adb_wo_alloca(&ndx, &schema_index, &ctx->db);
	adb_wo_alloca(&ctx->pkgs, &schema_pkginfo_array, &ctx->db);
	adb_wo_alloca(&ctx->pkginfo, &schema_pkginfo, &ctx->db);

	if (ctx->index) {
		apk_fileinfo_get(AT_FDCWD, ctx->index, 0, &fi, 0);
		index_mtime = fi.mtime;

		r = adb_m_open(&odb,
			adb_decompress(apk_istream_from_file_mmap(AT_FDCWD, ctx->index), NULL),
			ADB_SCHEMA_INDEX, trust);
		if (r) {
			apk_err(out, "%s: %s", ctx->index, apk_error_str(r));
			goto done;
		}
		adb_ro_obj(adb_r_rootobj(&odb, &oroot, &schema_index), ADBI_NDX_PACKAGES, &opkgs);
	}

	foreach_array_item(parg, args) {
		r = apk_fileinfo_get(AT_FDCWD, *parg, 0, &fi, 0);
		if (r < 0) {
		err_pkg:
			apk_err(out, "%s: %s", *parg, apk_error_str(r));
			errors++;
			continue;
		}
		ctx->file_size = fi.size;

		found = FALSE;
		if (index_mtime >= fi.mtime) {
			char *fname, *fend;
			apk_blob_t bname, bver;
			int i;

			/* Check that it looks like a package name */
			fname = strrchr(*parg, '/');
			if (fname == NULL)
				fname = *parg;
			else
				fname++;
			fend = strstr(fname, ".apk");
			if (!fend) goto do_file;
			if (apk_pkg_parse_name(APK_BLOB_PTR_PTR(fname, fend-1),
					       &bname, &bver) < 0)
				goto do_file;

			adb_wo_resetdb(&tmpl);
			adb_wo_blob(&tmpl, ADBI_PI_NAME, bname);
			adb_wo_blob(&tmpl, ADBI_PI_VERSION, bver);
			adb_wo_int(&tmpl, ADBI_PI_FILE_SIZE, fi.size);

			if ((i = adb_ra_find(&opkgs, 0, &tmpl)) > 0) {
				struct adb_obj pkg;
				adb_ro_obj(&opkgs, i, &pkg);

				val = adb_wa_append(&ctx->pkgs, adb_w_copy(&ctx->db, &odb, adb_ro_val(&opkgs, i)));
				found = TRUE;
			}
		}
		if (!found) {
		do_file:
			apk_digest_reset(&digest);
			apk_extract_reset(&ctx->ectx);
			apk_extract_generate_identity(&ctx->ectx, ctx->hash_alg, &digest);
			r = apk_extract(&ctx->ectx, apk_istream_from_file(AT_FDCWD, *parg));
			if (r < 0 && r != -ECANCELED) goto err_pkg;

			adb_wo_int(&ctx->pkginfo, ADBI_PI_FILE_SIZE, ctx->file_size);
			adb_wo_blob(&ctx->pkginfo, ADBI_PI_HASHES, APK_DIGEST_BLOB(digest));

			val = adb_wa_append_obj(&ctx->pkgs, &ctx->pkginfo);
			newpkgs++;
		}
		if (ADB_IS_ERROR(val)) errors++;
	}
	if (errors) {
		apk_err(out, "%d errors, not creating index", errors);
		r = -1;
		goto done;
	}

	numpkgs = adb_ra_num(&ctx->pkgs);
	adb_wo_blob(&ndx, ADBI_NDX_DESCRIPTION, APK_BLOB_STR(ctx->description));
	adb_wo_obj(&ndx, ADBI_NDX_PACKAGES, &ctx->pkgs);
	adb_w_rootobj(&ndx);

	r = adb_c_create(
		adb_compress(apk_ostream_to_file(AT_FDCWD, ctx->output, 0644), &ac->compspec),
		&ctx->db, trust);

	if (r == 0)
		apk_msg(out, "Index has %d packages (of which %d are new)", numpkgs, newpkgs);
	else
		apk_err(out, "Index creation failed: %s", apk_error_str(r));

done:
	adb_wo_free(&ctx->pkgs);
	adb_free(&ctx->db);
	adb_free(&odb);

#if 0
	apk_hash_foreach(&db->available.names, warn_if_no_providers, &counts);

	if (counts.unsatisfied != 0)
		apk_warn(out,
			"Total of %d unsatisfiable package names. Your repository may be broken.",
			counts.unsatisfied);
#endif

	return r;
}

static struct apk_applet apk_mkndx = {
	.name = "mkndx",
	.context_size = sizeof(struct mkndx_ctx),
	.optgroups = { &optgroup_global, &optgroup_generation, &optgroup_applet },
	.main = mkndx_main,
};

APK_DEFINE_APPLET(apk_mkndx);
