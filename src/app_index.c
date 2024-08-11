/* app_index.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "apk_applet.h"
#include "apk_database.h"
#include "apk_defines.h"
#include "apk_print.h"
#include "apk_tar.h"

#define APK_INDEXF_NO_WARNINGS	BIT(0)
#define APK_INDEXF_MERGE	BIT(1)
#define APK_INDEXF_PRUNE_ORIGIN	BIT(2)

struct counts {
	struct apk_indent indent;
	int unsatisfied;
	unsigned short header : 1;
};

struct index_ctx {
	const char *index;
	const char *output;
	const char *description;
	const char *rewrite_arch;
	time_t index_mtime;
	unsigned short index_flags;
};

#define INDEX_OPTIONS(OPT) \
	OPT(OPT_INDEX_description,	APK_OPT_ARG APK_OPT_SH("d") "description") \
	OPT(OPT_INDEX_index,		APK_OPT_ARG APK_OPT_SH("x") "index") \
	OPT(OPT_INDEX_merge,		"merge") \
	OPT(OPT_INDEX_no_warnings,	"no-warnings") \
	OPT(OPT_INDEX_output,		APK_OPT_ARG APK_OPT_SH("o") "output") \
	OPT(OPT_INDEX_prune_origin,	"prune-origin") \
	OPT(OPT_INDEX_rewrite_arch,	APK_OPT_ARG "rewrite-arch")

APK_OPT_APPLET(option_desc, INDEX_OPTIONS);

static int option_parse_applet(void *ctx, struct apk_ctx *ac, int opt, const char *optarg)
{
	struct index_ctx *ictx = (struct index_ctx *) ctx;

	switch (opt) {
	case OPT_INDEX_description:
		ictx->description = optarg;
		break;
	case OPT_INDEX_index:
		ictx->index = optarg;
		break;
	case OPT_INDEX_merge:
		ictx->index_flags |= APK_INDEXF_MERGE;
		break;
	case OPT_INDEX_output:
		ictx->output = optarg;
		break;
	case OPT_INDEX_prune_origin:
		ictx->index_flags |= APK_INDEXF_PRUNE_ORIGIN;
		break;
	case OPT_INDEX_rewrite_arch:
		ictx->rewrite_arch = optarg;
		break;
	case OPT_INDEX_no_warnings:
		ictx->index_flags |= APK_INDEXF_NO_WARNINGS;
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

struct index_writer {
	struct apk_ostream *os;
	int count;
	unsigned short index_flags;
};

static int index_write_entry(struct apk_database *db, const char *match, struct apk_package *pkg, void *ctx)
{
	struct index_writer *iw = ctx;

	switch (iw->index_flags & (APK_INDEXF_MERGE|APK_INDEXF_PRUNE_ORIGIN)) {
	case APK_INDEXF_MERGE:
		break;
	case APK_INDEXF_MERGE|APK_INDEXF_PRUNE_ORIGIN:
		if (!pkg->marked && pkg->origin) {
			struct apk_name *n = apk_db_query_name(db, *pkg->origin);
			if (n && n->state_int) return 0;
		}
		break;
	default:
		if (!pkg->marked) return 0;
		break;
	}

	iw->count++;
	return apk_pkg_write_index_entry(pkg, iw->os);
}

static int index_write(struct index_ctx *ictx, struct apk_database *db, struct apk_ostream *os)
{
	struct index_writer iw = {
		.index_flags = ictx->index_flags,
		.os = os,
	};

	apk_db_foreach_sorted_package(db, NULL, index_write_entry, &iw);

	return iw.count;
}

static int index_read_file(struct apk_database *db, struct index_ctx *ictx)
{
	struct apk_file_info fi;

	if (ictx->index == NULL)
		return 0;
	if (apk_fileinfo_get(AT_FDCWD, ictx->index, 0, &fi, &db->atoms) < 0)
		return 0;

	ictx->index_mtime = fi.mtime;
	return apk_db_index_read_file(db, ictx->index, 0);
}

static int warn_if_no_providers(struct apk_database *db, const char *match, struct apk_name *name, void *ctx)
{
	struct counts *counts = (struct counts *) ctx;

	if (!name->is_dependency) return 0;
	if (apk_array_len(name->providers) != 0) return 0;

	if (!counts->header) {
		apk_print_indented_group(&counts->indent, 2, "WARNING: No provider for the dependencies:\n");
		counts->header = 1;
	}
	apk_print_indented(&counts->indent, APK_BLOB_STR(name->name));
	counts->unsatisfied++;
	return 0;
}

static void index_mark_package(struct apk_database *db, struct apk_package *pkg, apk_blob_t *rewrite_arch)
{
	if (rewrite_arch) pkg->arch = rewrite_arch;
	pkg->marked = 1;
	if (pkg->origin) apk_db_get_name(db, *pkg->origin)->state_int = 1;
}

static int index_main(void *ctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	struct apk_out *out = &ac->out;
	struct apk_database *db = ac->db;
	struct counts counts = { .unsatisfied=0 };
	struct apk_ostream *os, *counter;
	struct apk_file_info fi;
	int total, r, found, newpkgs = 0, errors = 0;
	struct index_ctx *ictx = (struct index_ctx *) ctx;
	struct apk_package *pkg;
	char **parg;
	apk_blob_t *rewrite_arch = NULL;

	if (isatty(STDOUT_FILENO) && ictx->output == NULL &&
	    !(db->ctx->force & APK_FORCE_BINARY_STDOUT)) {
		apk_err(out,
			"Will not write binary index to console. "
			"Use --force-binary-stdout to override.");
		return -1;
	}

	if ((r = index_read_file(db, ictx)) < 0) {
		apk_err(out, "%s: %s", ictx->index, apk_error_str(r));
		return r;
	}

	if (ictx->rewrite_arch)
		rewrite_arch = apk_atomize(&db->atoms, APK_BLOB_STR(ictx->rewrite_arch));

	foreach_array_item(parg, args) {
		if (apk_fileinfo_get(AT_FDCWD, *parg, 0, &fi, &db->atoms) < 0) {
			apk_warn(out, "File '%s' is unaccessible", *parg);
			continue;
		}

		found = FALSE;
		do {
			struct apk_provider *p;
			struct apk_name *name;
			char *fname, *fend;
			apk_blob_t bname, bver;

			/* Check if index is newer than package */
			if (ictx->index == NULL || ictx->index_mtime < fi.mtime)
				break;

			/* Check that it looks like a package name */
			fname = strrchr(*parg, '/');
			if (fname == NULL)
				fname = *parg;
			else
				fname++;
			fend = strstr(fname, ".apk");
			if (fend == NULL)
				break;
			if (apk_pkg_parse_name(APK_BLOB_PTR_PTR(fname, fend-1),
					       &bname, &bver) < 0)
				break;

			/* If we have it in the old index already? */
			name = apk_db_query_name(db, bname);
			if (name == NULL)
				break;

			foreach_array_item(p, name->providers) {
				pkg = p->pkg;
				if (pkg->name != name) continue;
				if (apk_blob_compare(bver, *pkg->version) != 0) continue;
				if (pkg->size != fi.size) continue;
				index_mark_package(db, pkg, rewrite_arch);
				found = TRUE;
				break;
			}
		} while (0);

		if (!found) {
			r = apk_pkg_read(db, *parg, &pkg, FALSE);
			if (r < 0) {
				apk_err(out, "%s: %s", *parg, apk_error_str(r));
				errors++;
			} else {
				index_mark_package(db, pkg, rewrite_arch);
				newpkgs++;
			}
		}
	}
	if (errors)
		return -1;

	if (ictx->output != NULL)
		os = apk_ostream_to_file(AT_FDCWD, ictx->output, 0644);
	else
		os = apk_ostream_to_fd(STDOUT_FILENO);
	if (IS_ERR(os)) return PTR_ERR(os);

	memset(&fi, 0, sizeof(fi));
	fi.mode = 0644 | S_IFREG;
	fi.name = "APKINDEX";
	fi.mtime = apk_get_build_time();
	counter = apk_ostream_counter(&fi.size);
	index_write(ictx, db, counter);
	apk_ostream_close(counter);

	os = apk_ostream_gzip(os);
	if (ictx->description) {
		struct apk_file_info fi_desc;
		memset(&fi_desc, 0, sizeof(fi));
		fi_desc.mode = 0644 | S_IFREG;
		fi_desc.name = "DESCRIPTION";
		fi_desc.size = strlen(ictx->description);
		fi_desc.mtime = apk_get_build_time();
		apk_tar_write_entry(os, &fi_desc, ictx->description);
	}

	apk_tar_write_entry(os, &fi, NULL);
	index_write(ictx, db, os);
	apk_tar_write_padding(os, fi.size);
	apk_tar_write_entry(os, NULL, NULL);

	r = apk_ostream_close(os);
	if (r < 0) {
		apk_err(out, "Index generation failed: %s", apk_error_str(r));
		return r;
	}

	total = r;
	if (!(ictx->index_flags & APK_INDEXF_NO_WARNINGS)) {
		apk_print_indented_init(&counts.indent, out, 1);
		apk_db_foreach_sorted_name(db, NULL, warn_if_no_providers, &counts);
		apk_print_indented_end(&counts.indent);
	}

	if (counts.unsatisfied != 0)
		apk_warn(out,
			"Total of %d unsatisfiable package names. Your repository may be broken.",
			counts.unsatisfied);
	if (ictx->output != NULL)
		apk_msg(out, "Index has %d packages (of which %d are new)",
			total, newpkgs);
	return 0;
}

static struct apk_applet apk_index = {
	.name = "index",
	.open_flags = APK_OPENF_READ | APK_OPENF_NO_STATE | APK_OPENF_NO_REPOS,
	.context_size = sizeof(struct index_ctx),
	.optgroups = { &optgroup_global, &optgroup_applet },
	.main = index_main,
};

APK_DEFINE_APPLET(apk_index);

