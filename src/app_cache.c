/* app_cache.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <dirent.h>
#include <unistd.h>
#include <limits.h>

#include "apk_defines.h"
#include "apk_applet.h"
#include "apk_database.h"
#include "apk_package.h"
#include "apk_print.h"
#include "apk_solver.h"

#define CACHE_CLEAN	BIT(0)
#define CACHE_DOWNLOAD	BIT(1)

struct cache_ctx {
	unsigned short solver_flags;
	unsigned short add_dependencies : 1;
};

#define CACHE_OPTIONS(OPT) \
	OPT(OPT_CACHE_add_dependencies,	"add-dependencies") \
	OPT(OPT_CACHE_available,	APK_OPT_SH("a") "available") \
	OPT(OPT_CACHE_ignore_conflict,	"ignore-conflict") \
	OPT(OPT_CACHE_latest,		APK_OPT_SH("l") "latest") \
	OPT(OPT_CACHE_upgrade,		APK_OPT_SH("u") "upgrade") \
	OPT(OPT_CACHE_simulate,		APK_OPT_SH("s") "simulate") \

APK_OPT_APPLET(option_desc, CACHE_OPTIONS);

static int option_parse_applet(void *ctx, struct apk_ctx *ac, int opt, const char *optarg)
{
	struct cache_ctx *cctx = (struct cache_ctx *) ctx;

	switch (opt) {
	case OPT_CACHE_add_dependencies:
		cctx->add_dependencies = 1;
		break;
	case OPT_CACHE_available:
		cctx->solver_flags |= APK_SOLVERF_AVAILABLE;
		break;
	case OPT_CACHE_ignore_conflict:
		cctx->solver_flags |= APK_SOLVERF_IGNORE_CONFLICT;
		break;
	case OPT_CACHE_latest:
		cctx->solver_flags |= APK_SOLVERF_LATEST;
		break;
	case OPT_CACHE_upgrade:
		cctx->solver_flags |= APK_SOLVERF_UPGRADE;
		break;
	case OPT_CACHE_simulate:
		ac->flags |= APK_SIMULATE;
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

struct progress {
	struct apk_progress prog;
	size_t done, total;
};

static void progress_cb(void *ctx, size_t bytes_done)
{
	struct progress *prog = (struct progress *) ctx;
	apk_print_progress(&prog->prog, prog->done + bytes_done, prog->total);
}

static int cache_download(struct cache_ctx *cctx, struct apk_database *db, struct apk_string_array *args)
{
	struct apk_out *out = &db->ctx->out;
	struct apk_changeset changeset = {};
	struct apk_change *change;
	struct apk_package *pkg;
	struct apk_repository *repo;
	struct apk_dependency_array *deps;
	struct apk_dependency dep;
	struct progress prog = { .prog = db->ctx->progress };
	int i, r, ret = 0;

	apk_change_array_init(&changeset.changes);
	apk_dependency_array_init(&deps);
	if (apk_array_len(args) == 1 || cctx->add_dependencies)
		apk_dependency_array_copy(&deps, db->world);
	for (i = 1; i < apk_array_len(args); i++) {
		apk_blob_t b = APK_BLOB_STR(args->item[i]);
		apk_blob_pull_dep(&b, db, &dep);
		if (APK_BLOB_IS_NULL(b)) {
			apk_err(out, "bad dependency: %s", args->item[i]);
			return -EINVAL;
		}
		apk_dependency_array_add(&deps, dep);
	}
	r = apk_solver_solve(db, cctx->solver_flags, deps, &changeset);
	apk_dependency_array_free(&deps);
	if (r < 0) {
		apk_err(out, "Unable to select packages. Run apk fix.");
		return r;
	}

	foreach_array_item(change, changeset.changes) {
		pkg = change->new_pkg;
		if (!pkg || (pkg->repos & db->local_repos) || !pkg->installed_size)
			continue;
		if (!apk_db_select_repo(db, pkg)) continue;
		prog.total += pkg->size;
	}

	foreach_array_item(change, changeset.changes) {
		pkg = change->new_pkg;
		if (!pkg || (pkg->repos & db->local_repos) || !pkg->installed_size)
			continue;

		repo = apk_db_select_repo(db, pkg);
		if (repo == NULL)
			continue;

		r = apk_cache_download(db, repo, pkg, 0, progress_cb, &prog);
		if (r && r != -EALREADY) {
			apk_err(out, PKG_VER_FMT ": %s", PKG_VER_PRINTF(pkg), apk_error_str(r));
			ret++;
		}
		prog.done += pkg->size;
	}

	return ret;
}

static void cache_clean_item(struct apk_database *db, int static_cache, int dirfd, const char *name, struct apk_package *pkg)
{
	struct apk_out *out = &db->ctx->out;
	char tmp[PATH_MAX];
	apk_blob_t b;
	int i;

	if (!static_cache) {
		if (strcmp(name, "installed") == 0) return;
		if (pkg) {
			if (db->ctx->flags & APK_PURGE) {
				if (db->permanent || !pkg->ipkg) goto delete;
			}
			if (pkg->repos & db->local_repos & ~BIT(APK_REPOSITORY_CACHED)) goto delete;
			if (pkg->ipkg == NULL && !(pkg->repos & ~BIT(APK_REPOSITORY_CACHED))) goto delete;
			return;
		}
	}

	b = APK_BLOB_STR(name);
	for (i = 0; i < db->num_repos; i++) {
		/* Check if this is a valid index */
		apk_repo_format_cache_index(APK_BLOB_BUF(tmp), &db->repos[i]);
		if (apk_blob_compare(b, APK_BLOB_STR(tmp)) == 0) return;
	}

delete:
	apk_dbg(out, "deleting %s", name);
	if (!(db->ctx->flags & APK_SIMULATE)) {
		if (unlinkat(dirfd, name, 0) < 0 && errno == EISDIR)
			unlinkat(dirfd, name, AT_REMOVEDIR);
	}
}

static int cache_clean(struct apk_database *db)
{
	if (apk_db_cache_active(db)) {
		int r = apk_db_cache_foreach_item(db, cache_clean_item, 0);
		if (r) return r;
	}
	return apk_db_cache_foreach_item(db, cache_clean_item, 1);
}

static int cache_main(void *ctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	struct apk_database *db = ac->db;
	struct cache_ctx *cctx = (struct cache_ctx *) ctx;
	char *arg;
	int r = 0, actions = 0;

	if (apk_array_len(args) < 1) return -EINVAL;
	arg = args->item[0];
	if (strcmp(arg, "sync") == 0) {
		actions = CACHE_CLEAN | CACHE_DOWNLOAD;
	} else if (strcmp(arg, "clean") == 0) {
		actions = CACHE_CLEAN;
	} else if (strcmp(arg, "purge") == 0) {
		actions = CACHE_CLEAN;
		db->ctx->flags |= APK_PURGE;
	} else if (strcmp(arg, "download") == 0) {
		actions = CACHE_DOWNLOAD;
	} else
		return -EINVAL;

	if (!apk_db_cache_active(db))
		actions &= CACHE_CLEAN;

	if ((actions & CACHE_DOWNLOAD) && (cctx->solver_flags || cctx->add_dependencies)) {
		if (apk_db_repository_check(db) != 0) return 3;
	}

	if (r == 0 && (actions & CACHE_CLEAN))
		r = cache_clean(db);
	if (r == 0 && (actions & CACHE_DOWNLOAD))
		r = cache_download(cctx, db, args);

	return r;
}

static struct apk_applet apk_cache = {
	.name = "cache",
	.open_flags = APK_OPENF_READ|APK_OPENF_NO_SCRIPTS|APK_OPENF_CACHE_WRITE,
	.context_size = sizeof(struct cache_ctx),
	.optgroups = { &optgroup_global, &optgroup_applet },
	.main = cache_main,
};

APK_DEFINE_APPLET(apk_cache);
