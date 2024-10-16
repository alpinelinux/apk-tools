/* app_search.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2009 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <fnmatch.h>
#include <stdio.h>
#include "apk_defines.h"
#include "apk_applet.h"
#include "apk_package.h"
#include "apk_database.h"

struct search_ctx {
	void (*print_result)(struct search_ctx *ctx, struct apk_package *pkg);
	void (*print_package)(struct search_ctx *ctx, struct apk_package *pkg);

	int verbosity;
	unsigned int show_all : 1;
	unsigned int search_exact : 1;
	unsigned int search_description : 1;
	unsigned int search_origin : 1;

	unsigned int matches;
	struct apk_string_array *filter;
	struct apk_package *prev_match;
};

static void print_package_name(struct search_ctx *ctx, struct apk_package *pkg)
{
	printf("%s", pkg->name->name);
	if (ctx->verbosity > 0)
		printf("-" BLOB_FMT, BLOB_PRINTF(*pkg->version));
	if (ctx->verbosity > 1)
		printf(" - " BLOB_FMT, BLOB_PRINTF(*pkg->description));
	printf("\n");
}

static void print_origin_name(struct search_ctx *ctx, struct apk_package *pkg)
{
	if (pkg->origin != NULL)
		printf(BLOB_FMT, BLOB_PRINTF(*pkg->origin));
	else
		printf("%s", pkg->name->name);
	if (ctx->verbosity > 0)
		printf("-" BLOB_FMT, BLOB_PRINTF(*pkg->version));
	printf("\n");
}

static void print_rdep_pkg(struct apk_package *pkg0, struct apk_dependency *dep0, struct apk_package *pkg, void *pctx)
{
	struct search_ctx *ctx = (struct search_ctx *) pctx;
	ctx->print_package(ctx, pkg0);
}

static void print_rdepends(struct search_ctx *ctx, struct apk_package *pkg)
{
	if (ctx->verbosity > 0) {
		ctx->matches = apk_foreach_genid() | APK_DEP_SATISFIES;
		printf(PKG_VER_FMT " is required by:\n", PKG_VER_PRINTF(pkg));
	}
	apk_pkg_foreach_reverse_dependency(pkg, ctx->matches, print_rdep_pkg, ctx);
}

#define SEARCH_OPTIONS(OPT) \
	OPT(OPT_SEARCH_all,		APK_OPT_SH("a") "all") \
	OPT(OPT_SEARCH_description,	APK_OPT_SH("d") "description") \
	OPT(OPT_SEARCH_exact,		APK_OPT_S2("ex") "exact") \
	OPT(OPT_SEARCH_has_origin,	"has-origin") \
	OPT(OPT_SEARCH_origin,		APK_OPT_SH("o") "origin") \
	OPT(OPT_SEARCH_rdepends,	APK_OPT_SH("r") "rdepends") \

APK_OPT_APPLET(option_desc, SEARCH_OPTIONS);

static int option_parse_applet(void *ctx, struct apk_ctx *ac, int opt, const char *optarg)
{
	struct search_ctx *ictx = (struct search_ctx *) ctx;

	switch (opt) {
	case OPT_SEARCH_all:
		ictx->show_all = 1;
		break;
	case OPT_SEARCH_description:
		ictx->search_description = 1;
		ictx->show_all = 1;
		break;
	case OPT_SEARCH_exact:
		ictx->search_exact = 1;
		break;
	case OPT_SEARCH_origin:
		ictx->print_package = print_origin_name;
		break;
	case OPT_SEARCH_rdepends:
		ictx->print_result = print_rdepends;
		break;
	case OPT_SEARCH_has_origin:
		ictx->search_origin = 1;
		ictx->search_exact = 1;
		ictx->show_all = 1;
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

static void print_result_pkg(struct search_ctx *ctx, struct apk_package *pkg)
{
	char **pmatch;

	if (ctx->search_description) {
		foreach_array_item(pmatch, ctx->filter) {
			if (fnmatch(*pmatch, pkg->description->ptr, FNM_CASEFOLD) == 0 ||
			    fnmatch(*pmatch, pkg->name->name, FNM_CASEFOLD) == 0)
				goto match;
		}
		return;
	}
	if (ctx->search_origin) {
		foreach_array_item(pmatch, ctx->filter) {
			if (!pkg->origin) continue;
			if (apk_blob_compare(APK_BLOB_STR(*pmatch), *pkg->origin) == 0)
				goto match;
		}
		return;
	}
match:
	ctx->print_result(ctx, pkg);
}

static int print_result(struct apk_database *db, const char *match, struct apk_package *pkg, void *pctx)
{
	struct search_ctx *ctx = pctx;

	if (!pkg) return 0;

	if (ctx->show_all) {
		print_result_pkg(ctx, pkg);
		return 0;
	}

	if (!ctx->prev_match) {
		ctx->prev_match = pkg;
		return 0;
	}
	if (ctx->prev_match->name != pkg->name) {
		print_result_pkg(ctx, ctx->prev_match);
		ctx->prev_match = pkg;
		return 0;
	}
	if (apk_pkg_version_compare(pkg, ctx->prev_match) == APK_VERSION_GREATER)
		ctx->prev_match = pkg;
	return 0;
}

static int search_main(void *pctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	struct apk_database *db = ac->db;
	struct search_ctx *ctx = (struct search_ctx *) pctx;
	char **pmatch;

	ctx->verbosity = apk_out_verbosity(&db->ctx->out);
	ctx->filter = args;
	ctx->matches = apk_foreach_genid() | APK_DEP_SATISFIES;
	if (ctx->print_package == NULL)
		ctx->print_package = print_package_name;
	if (ctx->print_result == NULL)
		ctx->print_result = ctx->print_package;

	if (ctx->search_description || ctx->search_origin) {
		// Just enumerate all names in sorted order, and do the
		// filtering in the callback.
		args = NULL;
	}

	if (!ctx->search_exact) {
		foreach_array_item(pmatch, ctx->filter) {
			size_t slen = strlen(*pmatch) + 3;
			*pmatch = apk_fmts(alloca(slen), slen, "*%s*", *pmatch);
		}
	}
	apk_db_foreach_sorted_providers(db, args, print_result, ctx);
	if (ctx->prev_match) print_result_pkg(ctx, ctx->prev_match);

	return 0;
}

static struct apk_applet apk_search = {
	.name = "search",
	.open_flags = APK_OPENF_READ | APK_OPENF_NO_STATE | APK_OPENF_ALLOW_ARCH,
	.context_size = sizeof(struct search_ctx),
	.optgroups = { &optgroup_global, &optgroup_source, &optgroup_applet },
	.main = search_main,
};

APK_DEFINE_APPLET(apk_search);
