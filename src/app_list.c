/* app_list.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2009 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * Copyright (C) 2018 William Pitcock <nenolod@dereferenced.org>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include "apk_defines.h"
#include "apk_applet.h"
#include "apk_package.h"
#include "apk_database.h"
#include "apk_print.h"

struct list_ctx {
	int verbosity;
	unsigned int installed : 1;
	unsigned int orphaned : 1;
	unsigned int available : 1;
	unsigned int upgradable : 1;
	unsigned int match_origin : 1;
	unsigned int match_depends : 1;
	unsigned int match_providers : 1;
	unsigned int manifest : 1;

	struct apk_string_array *filters;
};

static int origin_matches(const struct list_ctx *ctx, const struct apk_package *pkg)
{
	char **pmatch;

	if (pkg->origin == NULL)
		return 0;

	foreach_array_item(pmatch, ctx->filters) {
		if (apk_blob_compare(APK_BLOB_STR(*pmatch), *pkg->origin) == 0)
			return 1;
	}

	return 0;
}

static int is_orphaned(const struct apk_name *name)
{
	struct apk_provider *p;
	unsigned int repos = 0;

	if (name == NULL)
		return 0;

	foreach_array_item(p, name->providers)
		repos |= p->pkg->repos;

	/* repo 1 is always installed-db, so if other bits are set it means the package is available somewhere
	 * (either cache or in a proper repo)
	 */
	return (repos & ~BIT(APK_REPOSITORY_CACHED)) == 0;
}

/* returns the currently installed package if 'pkg' is a newer and installable version */
static const struct apk_package *is_upgradable(const struct apk_database *db, const struct apk_package *pkg)
{
	struct apk_name *name = pkg->name;
	struct apk_package *ipkg;
	unsigned short allowed_repos;

	ipkg = apk_pkg_get_installed(name);
	if (!ipkg) return NULL;

	allowed_repos = db->repo_tags[ipkg->ipkg->repository_tag].allowed_repos;
	if (!(pkg->repos & allowed_repos)) return NULL;

	return apk_version_match(*ipkg->version, APK_VERSION_LESS, *pkg->version) ? ipkg : NULL;
}

static void print_package(const struct apk_database *db, const struct apk_package *pkg, const struct list_ctx *ctx)
{
	if (ctx->verbosity <= 0) {
		printf("%s\n", pkg->name->name);
		return;
	}

	printf(PKG_VER_FMT " " BLOB_FMT " ",
		PKG_VER_PRINTF(pkg), BLOB_PRINTF(*pkg->arch));

	if (pkg->origin != NULL)
		printf("{" BLOB_FMT "}", BLOB_PRINTF(*pkg->origin));
	else
		printf("{%s}", pkg->name->name);

	printf(" (" BLOB_FMT ")", BLOB_PRINTF(*pkg->license));

	if (pkg->ipkg)
		printf(" [installed]");
	else {
		const struct apk_package *u = is_upgradable(db, pkg);
		if (u != NULL) printf(" [upgradable from: " PKG_VER_FMT "]", PKG_VER_PRINTF(u));
	}


	if (ctx->verbosity > 1) {
		printf("\n  " BLOB_FMT "\n", BLOB_PRINTF(*pkg->description));
		if (ctx->verbosity > 2)
			printf("  <"BLOB_FMT">\n", BLOB_PRINTF(*pkg->url));
	}

	printf("\n");
}

static void print_manifest(const struct apk_package *pkg, const struct list_ctx *ctx)
{
	printf("%s " BLOB_FMT "\n", pkg->name->name, BLOB_PRINTF(*pkg->version));
}

static void filter_package(const struct apk_database *db, const struct apk_package *pkg, const struct list_ctx *ctx, const struct apk_name *name)
{
	if (ctx->match_origin && !origin_matches(ctx, pkg))
		return;

	if (ctx->installed && pkg->ipkg == NULL)
		return;

	if (ctx->orphaned && !is_orphaned(pkg->name))
		return;

	if (ctx->available && pkg->repos == BIT(APK_REPOSITORY_CACHED))
		return;

	if (ctx->upgradable && !is_upgradable(db, pkg))
		return;

	if (ctx->match_providers)
		printf("<%s> ", name->name);

	if (ctx->manifest)
		print_manifest(pkg, ctx);
	else
		print_package(db, pkg, ctx);
}

static void iterate_providers(const struct apk_database *db, const struct apk_name *name, const struct list_ctx *ctx)
{
	struct apk_provider *p;

	foreach_array_item(p, name->providers) {
		if (!ctx->match_providers && p->pkg->name != name)
			continue;

		filter_package(db, p->pkg, ctx, name);
	}
}

static int print_result(struct apk_database *db, const char *match, struct apk_name *name, void *pctx)
{
	struct list_ctx *ctx = pctx;
	struct apk_name **pname;

	if (!name) return 0;

	apk_name_sorted_providers(name);
	if (ctx->match_depends) {
		foreach_array_item(pname, name->rdepends)
			iterate_providers(db, *pname, ctx);
	} else {
		iterate_providers(db, name, ctx);
	}
	return 0;
}

#define LIST_OPTIONS(OPT) \
	OPT(OPT_LIST_available,		APK_OPT_SH("a") "available") \
	OPT(OPT_LIST_depends,		APK_OPT_SH("d") "depends") \
	OPT(OPT_LIST_installed,		APK_OPT_SH("I") "installed") \
	OPT(OPT_LIST_manifest,		"manifest") \
	OPT(OPT_LIST_origin,		APK_OPT_SH("o") "origin") \
	OPT(OPT_LIST_orphaned,		APK_OPT_SH("O") "orphaned") \
	OPT(OPT_LIST_providers,		APK_OPT_SH("P") "providers") \
	OPT(OPT_LIST_upgradable,	APK_OPT_SH("u") "upgradable") \
	OPT(OPT_LIST_upgradeable,	"upgradeable")

APK_OPT_APPLET(option_desc, LIST_OPTIONS);

static int option_parse_applet(void *pctx, struct apk_ctx *ac, int opt, const char *optarg)
{
	struct list_ctx *ctx = pctx;

	switch (opt) {
	case OPT_LIST_available:
		ctx->available = 1;
		ctx->orphaned = 0;
		break;
	case OPT_LIST_depends:
		ctx->match_depends = 1;
		break;
	case OPT_LIST_installed:
		ctx->installed = 1;
		ac->open_flags |= APK_OPENF_NO_SYS_REPOS;
		break;
	case OPT_LIST_manifest:
		ctx->manifest = 1;
		ctx->installed = 1;
		break;
	case OPT_LIST_origin:
		ctx->match_origin = 1;
		break;
	case OPT_LIST_orphaned:
		ctx->installed = 1;
		ctx->orphaned = 1;
		break;
	case OPT_LIST_providers:
		ctx->match_providers = 1;
		break;
	case OPT_LIST_upgradable:
	case OPT_LIST_upgradeable:
		ctx->available = 1;
		ctx->orphaned = 0;
		ctx->installed = 0;
		ctx->upgradable = 1;
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

static int list_main(void *pctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	struct apk_out *out = &ac->out;
	struct apk_database *db = ac->db;
	struct list_ctx *ctx = pctx;

	ctx->verbosity = apk_out_verbosity(out);
	ctx->filters = args;

	if (ctx->match_origin)
		args = NULL;

	apk_db_foreach_sorted_name(db, args, print_result, ctx);
	return 0;
}

static struct apk_applet apk_list = {
	.name = "list",
	.open_flags = APK_OPENF_READ | APK_OPENF_ALLOW_ARCH,
	.context_size = sizeof(struct list_ctx),
	.optgroups = { &optgroup_global, &optgroup_source, &optgroup_applet },
	.main = list_main,
};

APK_DEFINE_APPLET(apk_list);
