/* app_upgrade.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "apk_applet.h"
#include "apk_database.h"
#include "apk_print.h"
#include "apk_solver.h"

// APK_SELFUPGRADE_TOKEN is used to determine if APK version changed
// so much after self-upgrade that a repository autoupdate should be
// enabled. Mainly needed if the index cache name changes.
#define APK_SELFUPGRADE_TOKEN	"laiNgeiThu6ip1Te"

extern char **apk_argv;

struct upgrade_ctx {
	unsigned short solver_flags;
	unsigned short no_self_upgrade : 1;
	unsigned short self_upgrade_only : 1;
	unsigned short ignore : 1;
	unsigned short prune : 1;
	int errors;
};

#define UPGRADE_OPTIONS(OPT) \
	OPT(OPT_UPGRADE_available,		APK_OPT_SH("a") "available") \
	OPT(OPT_UPGRADE_ignore,			"ignore") \
	OPT(OPT_UPGRADE_latest,			APK_OPT_SH("l") "latest") \
	OPT(OPT_UPGRADE_no_self_upgrade,	"no-self-upgrade") \
	OPT(OPT_UPGRADE_prune,			"prune") \
	OPT(OPT_UPGRADE_self_upgrade_only,	"self-upgrade-only")

APK_OPTIONS(upgrade_options_desc, UPGRADE_OPTIONS);

static int upgrade_parse_option(void *ctx, struct apk_ctx *ac, int opt, const char *optarg)
{
	struct upgrade_ctx *uctx = (struct upgrade_ctx *) ctx;
	const char *token;

	switch (opt) {
	case APK_OPTIONS_INIT:
		token = getenv("APK_SELFUPGRADE_TOKEN");
		if (token != NULL && strcmp(token, APK_SELFUPGRADE_TOKEN) == 0) {
			uctx->no_self_upgrade = 1;
			ac->open_flags |= APK_OPENF_NO_AUTOUPDATE;
		}
		break;
	case OPT_UPGRADE_no_self_upgrade:
		uctx->no_self_upgrade = 1;
		break;
	case OPT_UPGRADE_self_upgrade_only:
		uctx->self_upgrade_only = 1;
		break;
	case OPT_UPGRADE_ignore:
		uctx->ignore = 1;
		break;
	case OPT_UPGRADE_prune:
		uctx->prune = 1;
		break;
	case OPT_UPGRADE_available:
		uctx->solver_flags |= APK_SOLVERF_AVAILABLE;
		break;
	case OPT_UPGRADE_latest:
		uctx->solver_flags |= APK_SOLVERF_LATEST;
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

int apk_do_self_upgrade(struct apk_database *db, unsigned short solver_flags, unsigned int self_upgrade_only)
{
	struct apk_out *out = &db->ctx->out;
	struct apk_changeset changeset = {};
	struct apk_query_match qm;
	char buf[PATH_MAX];
	int r = 0;

	apk_change_array_init(&changeset.changes);

	apk_query_who_owns(db, "/proc/self/exe", &qm, buf, sizeof buf);
	if (!qm.pkg) goto ret;

	/* First check if new version is even available */
	struct apk_package *pkg = qm.pkg;
	struct apk_name *name = pkg->name;
	apk_array_foreach(p0, name->providers) {
		struct apk_package *pkg0 = p0->pkg;
		if (pkg0->name != name || pkg0->repos == 0)
			continue;
		if (apk_version_match(*pkg0->version, APK_VERSION_GREATER, *pkg->version)) {
			r = 1;
			break;
		}
	}
	if (r == 0) goto ret;

	/* Create new commit upgrading apk-tools only with minimal other changes */
	db->performing_self_upgrade = 1;
	apk_solver_set_name_flags(name, solver_flags, 0);

	r = apk_solver_solve(db, 0, db->world, &changeset);
	if (r != 0) {
		apk_warn(out, "Failed to perform initial self-upgrade, continuing with full upgrade.");
		r = 0;
		goto ret;
	}

	if (changeset.num_total_changes == 0)
		goto ret;

	if (!self_upgrade_only && db->ctx->flags & APK_SIMULATE) {
		apk_warn(out, "This simulation is not reliable as apk-tools upgrade is available.");
		goto ret;
	}

	apk_msg(out, "Upgrading critical system libraries and apk-tools:");
	apk_solver_commit_changeset(db, &changeset, db->world);
	if (self_upgrade_only) goto ret;

	apk_db_close(db);

	apk_msg(out, "Continuing the upgrade transaction with new apk-tools:");
	putenv("APK_SELFUPGRADE_TOKEN=" APK_SELFUPGRADE_TOKEN);

	for (r = 0; apk_argv[r] != NULL; r++)
		;
	apk_argv[r] = "--no-self-upgrade";
	execvp(apk_argv[0], apk_argv);

	apk_err(out, "PANIC! Failed to re-execute new apk-tools!");
	exit(1);

ret:
	apk_change_array_free(&changeset.changes);
	db->performing_self_upgrade = 0;
	return r;
}

static int set_upgrade_for_name(struct apk_database *db, const char *match, struct apk_name *name, void *pctx)
{
	struct apk_out *out = &db->ctx->out;
	struct upgrade_ctx *uctx = (struct upgrade_ctx *) pctx;

	if (!name) {
		apk_err(out, "Package '%s' not found", match);
		uctx->errors++;
		return 0;
	}

	apk_solver_set_name_flags(name, uctx->ignore ? APK_SOLVERF_INSTALLED : APK_SOLVERF_UPGRADE, 0);
	return 0;
}

static int upgrade_main(void *ctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	struct apk_out *out = &ac->out;
	struct apk_database *db = ac->db;
	struct upgrade_ctx *uctx = (struct upgrade_ctx *) ctx;
	unsigned short solver_flags;
	struct apk_dependency_array *world;
	int r = 0;

	apk_dependency_array_init(&world);
	if (apk_db_check_world(db, db->world) != 0) {
		apk_err(out, "Not continuing with upgrade due to missing repository tags.");
		return -1;
	}
	if (apk_db_repository_check(db) != 0) return -1;

	solver_flags = APK_SOLVERF_UPGRADE | uctx->solver_flags;
	if ((uctx->self_upgrade_only || !ac->root_set) && !uctx->no_self_upgrade && apk_array_len(args) == 0) {
		r = apk_do_self_upgrade(db, solver_flags, uctx->self_upgrade_only);
		if (r != 0)
			return r;
	}
	if (uctx->self_upgrade_only)
		return 0;

	if (uctx->prune || (solver_flags & APK_SOLVERF_AVAILABLE)) {
		apk_dependency_array_copy(&world, db->world);
		if (solver_flags & APK_SOLVERF_AVAILABLE) {
			apk_array_foreach(dep, world) {
				if (dep->op == APK_DEPMASK_CHECKSUM) {
					dep->op = APK_DEPMASK_ANY;
					dep->version = &apk_atom_null;
				}
			}
		}
		if (uctx->prune) {
			int i, j;
			for (i = j = 0; i < apk_array_len(world); i++) {
				apk_array_foreach(p, world->item[i].name->providers) {
					if (apk_db_pkg_available(db, p->pkg)) {
						world->item[j++] = world->item[i];
						break;
					}
				}
			}
			apk_array_truncate(world, j);
		}
	} else {
		world = db->world;
	}

	if (apk_array_len(args) > 0) {
		/* if specific packages are listed, we don't want to upgrade world. */
		if (!uctx->ignore) solver_flags &= ~APK_SOLVERF_UPGRADE;
		apk_db_foreach_matching_name(db, args, set_upgrade_for_name, uctx);
		if (uctx->errors) return uctx->errors;
	}

	r = apk_solver_commit(db, solver_flags, world);

	if (world != db->world) apk_dependency_array_free(&world);
	return r;
}

static struct apk_applet apk_upgrade = {
	.name = "upgrade",
	.options_desc = upgrade_options_desc,
	.optgroup_commit = 1,
	.open_flags = APK_OPENF_WRITE,
	.context_size = sizeof(struct upgrade_ctx),
	.parse = upgrade_parse_option,
	.main = upgrade_main,
};

APK_DEFINE_APPLET(apk_upgrade);
