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
	unsigned int installed : 1;
	unsigned int orphaned : 1;
	unsigned int available : 1;
	unsigned int upgradable : 1;
	unsigned int match_origin : 1;
	unsigned int match_depends : 1;
	unsigned int match_providers : 1;

	struct apk_string_array *filters;
};

static int origin_matches(const struct list_ctx *ctx, const struct apk_package *pkg)
{
	char **pmatch;

	if (pkg->origin == NULL)
		return 0;

	foreach_array_item(pmatch, ctx->filters)
	{
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

/* returns the currently installed package if there is a newer package that satisfies `name` */
static const struct apk_package *is_upgradable(struct apk_name *name, const struct apk_package *pkg0)
{
	struct apk_provider *p;
	struct apk_package *ipkg;
	apk_blob_t no_version = APK_BLOB_STR("");
	apk_blob_t *latest = &no_version;
	int r;

	if (!name) return NULL;

	ipkg = apk_pkg_get_installed(name);
	if (!ipkg) return NULL;

	if (!pkg0) {
		foreach_array_item(p, name->providers) {
			pkg0 = p->pkg;
			if (pkg0 == ipkg) continue;
			r = apk_version_compare_blob(*pkg0->version, *latest);
			if (r == APK_VERSION_GREATER) latest = pkg0->version;
		}
	} else {
		latest = pkg0->version;
	}
	return apk_version_compare_blob(*ipkg->version, *latest) == APK_VERSION_LESS ? ipkg : NULL;
}

static void print_package(const struct apk_package *pkg, const struct list_ctx *ctx)
{
	printf(PKG_VER_FMT " " BLOB_FMT " ",
		PKG_VER_PRINTF(pkg), BLOB_PRINTF(*pkg->arch));

	if (pkg->origin != NULL)
		printf("{" BLOB_FMT "}", BLOB_PRINTF(*pkg->origin));
	else
		printf("{%s}", pkg->name->name);

	printf(" (" BLOB_FMT ")", BLOB_PRINTF(*pkg->license));

	if (pkg->ipkg)
		printf(" [installed]");
	else
	{
		const struct apk_package *u;

		u = is_upgradable(pkg->name, pkg);
		if (u != NULL)
			printf(" [upgradable from: " PKG_VER_FMT "]", PKG_VER_PRINTF(u));
	}


	if (apk_verbosity > 1)
	{
		printf("\n  %s\n", pkg->description);
		if (apk_verbosity > 2)
			printf("  <%s>\n", pkg->url);
	}

	printf("\n");
}

static void filter_package(const struct apk_package *pkg, const struct list_ctx *ctx)
{
	if (ctx->match_origin && !origin_matches(ctx, pkg))
		return;

	if (ctx->installed && pkg->ipkg == NULL)
		return;

	if (ctx->orphaned && !is_orphaned(pkg->name))
		return;

	if (ctx->available && pkg->repos == BIT(APK_REPOSITORY_CACHED))
		return;

	if (ctx->upgradable && !is_upgradable(pkg->name, pkg))
		return;

	print_package(pkg, ctx);
}

static void iterate_providers(const struct apk_name *name, const struct list_ctx *ctx)
{
	struct apk_provider *p;

	foreach_array_item(p, name->providers)
	{
		if (!ctx->match_providers && p->pkg->name != name)
			continue;

		if (ctx->match_providers)
			printf("<%s> ", name->name);

		filter_package(p->pkg, ctx);
	}
}

static void print_result(struct apk_database *db, const char *match, struct apk_name *name, void *pctx)
{
	struct list_ctx *ctx = pctx;

	if (name == NULL)
		return;

	if (ctx->match_depends)
	{
		struct apk_name **pname;

		foreach_array_item(pname, name->rdepends)
			iterate_providers(*pname, ctx);
	}
	else
		iterate_providers(name, ctx);
}

enum {
	OPT_LIST_available,
	OPT_LIST_installed,
	OPT_LIST_depends,
	OPT_LIST_origin,
	OPT_LIST_orphaned,
	OPT_LIST_providers,
	OPT_LIST_upgradeable,
};

static const char option_desc[] =
	APK_OPTAPPLET
	APK_OPT2n("available", "a")
	APK_OPT2n("installed", "I")
	APK_OPT2n("depends", "d")
	APK_OPT2n("origin", "o")
	APK_OPT2n("orphaned", "O")
	APK_OPT2n("providers", "P")
	APK_OPT2n("upgradeable", "u");

static int option_parse_applet(void *pctx, struct apk_db_options *dbopts, int opt, const char *optarg)
{
	struct list_ctx *ctx = pctx;

	switch (opt) {
	case OPT_LIST_available:
		ctx->available = 1;
		ctx->orphaned = 0;
		break;
	case OPT_LIST_installed:
		ctx->installed = 1;
		break;
	case OPT_LIST_depends:
		ctx->match_depends = 1;
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

static int list_main(void *pctx, struct apk_database *db, struct apk_string_array *args)
{
	struct list_ctx *ctx = pctx;

	ctx->filters = args;

	if (ctx->match_origin)
		args = NULL;

	apk_name_foreach_matching(
		db, args, APK_FOREACH_NULL_MATCHES_ALL | apk_foreach_genid(),
		print_result, ctx);

	return 0;
}

static struct apk_applet apk_list = {
	.name = "list",
	.open_flags = APK_OPENF_READ,
	.context_size = sizeof(struct list_ctx),
	.optgroups = { &optgroup_global, &optgroup_applet },
	.main = list_main,
};

APK_DEFINE_APPLET(apk_list);
