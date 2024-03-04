/* app_fix.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>
#include "apk_applet.h"
#include "apk_database.h"
#include "apk_print.h"
#include "apk_solver.h"

struct fix_ctx {
	unsigned short solver_flags;
	int fix_depends : 1;
	int fix_xattrs : 1;
	int fix_directory_permissions : 1;
	int errors;
};

#define FIX_OPTIONS(OPT) \
	OPT(OPT_FIX_depends,			APK_OPT_SH("d") "depends") \
	OPT(OPT_FIX_directory_permissions,	"directory-permissions") \
	OPT(OPT_FIX_reinstall,			APK_OPT_SH("r") "reinstall") \
	OPT(OPT_FIX_upgrade,			APK_OPT_SH("u") "upgrade") \
	OPT(OPT_FIX_xattr,			APK_OPT_SH("x") "xattr")

APK_OPT_APPLET(option_desc, FIX_OPTIONS);

static int option_parse_applet(void *pctx, struct apk_db_options *dbopts, int opt, const char *optarg)
{
	struct fix_ctx *ctx = (struct fix_ctx *) pctx;
	switch (opt) {
	case OPT_FIX_depends:
		ctx->fix_depends = 1;
		break;
	case OPT_FIX_directory_permissions:
		ctx->fix_directory_permissions = 1;
		break;
	case OPT_FIX_reinstall:
		ctx->solver_flags |= APK_SOLVERF_REINSTALL;
		break;
	case OPT_FIX_upgrade:
		ctx->solver_flags |= APK_SOLVERF_UPGRADE;
		break;
	case OPT_FIX_xattr:
		ctx->fix_xattrs = 1;
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

static int mark_recalculate(apk_hash_item item, void *ctx)
{
	struct apk_db_dir *dir = (struct apk_db_dir *) item;
	if (dir->refs == 0) return 0;
	dir->update_permissions = 1;
	return 0;
}

static void mark_fix(struct fix_ctx *ctx, struct apk_name *name)
{
	apk_solver_set_name_flags(name, ctx->solver_flags, ctx->fix_depends ? ctx->solver_flags : 0);
}

static int set_solver_flags(struct apk_database *db, const char *match, struct apk_name *name, void *pctx)
{
	struct fix_ctx *ctx = pctx;

	if (!name) {
		apk_error("Package '%s' not found", match);
		ctx->errors++;
		return 0;
	}

	mark_fix(ctx, name);
	return 0;
}

static int fix_main(void *pctx, struct apk_database *db, struct apk_string_array *args)
{
	struct fix_ctx *ctx = (struct fix_ctx *) pctx;
	struct apk_installed_package *ipkg;

	if (!ctx->solver_flags)
		ctx->solver_flags = APK_SOLVERF_REINSTALL;

	if (ctx->fix_directory_permissions)
		apk_hash_foreach(&db->installed.dirs, mark_recalculate, db);

	if (args->num == 0) {
		list_for_each_entry(ipkg, &db->installed.packages, installed_pkgs_list) {
			if (ipkg->broken_files || ipkg->broken_script ||
			    (ipkg->broken_xattr && ctx->fix_xattrs))
				mark_fix(ctx, ipkg->pkg->name);
		}
	} else
		apk_db_foreach_matching_name(db, args, set_solver_flags, ctx);

	if (ctx->errors) return ctx->errors;

	return apk_solver_commit(db, 0, db->world);
}

static struct apk_applet apk_fix = {
	.name = "fix",
	.open_flags = APK_OPENF_WRITE,
	.remove_empty_arguments = 1,
	.context_size = sizeof(struct fix_ctx),
	.optgroups = { &optgroup_global, &optgroup_commit, &optgroup_applet },
	.main = fix_main,
};

APK_DEFINE_APPLET(apk_fix);

