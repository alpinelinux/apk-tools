/* app_add.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include "apk_applet.h"
#include "apk_database.h"
#include "apk_print.h"
#include "apk_solver.h"

struct add_ctx {
	const char *virtpkg;
	unsigned short solver_flags;
};

#define ADD_OPTIONS(OPT) \
	OPT(OPT_ADD_initdb,	"initdb") \
	OPT(OPT_ADD_latest,	APK_OPT_SH("l") "latest") \
	OPT(OPT_ADD_no_chown,   "no-chown") \
	OPT(OPT_ADD_upgrade,	APK_OPT_SH("u") "upgrade") \
	OPT(OPT_ADD_usermode,	"usermode") \
	OPT(OPT_ADD_virtual,	APK_OPT_ARG APK_OPT_SH("t") "virtual")

APK_OPT_APPLET(option_desc, ADD_OPTIONS);

static int option_parse_applet(void *ctx, struct apk_ctx *ac, int opt, const char *optarg)
{
	struct add_ctx *actx = (struct add_ctx *) ctx;

	switch (opt) {
	case OPT_ADD_initdb:
		ac->open_flags |= APK_OPENF_CREATE;
		break;
	case OPT_ADD_latest:
		actx->solver_flags |= APK_SOLVERF_LATEST;
		break;
	case OPT_ADD_usermode:
	case OPT_ADD_no_chown:
		ac->open_flags |= APK_OPENF_USERMODE;
		break;
	case OPT_ADD_upgrade:
		actx->solver_flags |= APK_SOLVERF_UPGRADE;
		break;
	case OPT_ADD_virtual:
		actx->virtpkg = optarg;
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

static int non_repository_check(struct apk_database *db)
{
	if (db->ctx->force & APK_FORCE_NON_REPOSITORY)
		return 0;
	if (apk_db_cache_active(db))
		return 0;
	if (apk_db_permanent(db))
		return 0;

	apk_err(&db->ctx->out,
		"You tried to add a non-repository package to system, "
		"but it would be lost on next reboot. Enable package caching "
		"(apk cache --help) or use --force-non-repository "
		"if you know what you are doing.");
	return 1;
}

static void create_virtual_package(struct apk_package_tmpl *virtpkg, struct apk_database *db, struct apk_dependency *dep)
{
	struct apk_digest_ctx dctx;
	pid_t pid = getpid();

	virtpkg->pkg.name = dep->name;
	virtpkg->pkg.version = dep->version;
	virtpkg->pkg.description = apk_atomize_dup0(&db->atoms, APK_BLOB_STRLIT("virtual meta package"));
	virtpkg->pkg.arch = apk_atomize(&db->atoms, APK_BLOB_STRLIT("noarch"));
	virtpkg->pkg.repos |= BIT(APK_REPOSITORY_CACHED);

	apk_digest_ctx_init(&dctx, APK_DIGEST_SHA1);
	apk_digest_ctx_update(&dctx, &pid, sizeof pid);
	apk_digest_ctx_update(&dctx, dep->name->name, strlen(dep->name->name) + 1);
	apk_digest_ctx_update(&dctx, dep->version->ptr, dep->version->len);
	apk_digest_ctx_final(&dctx, &virtpkg->id);
	apk_digest_ctx_free(&dctx);
}

static apk_blob_t *generate_version(struct apk_database *db)
{
	char ver[32];
	struct tm tm;
	time_t now = time(NULL);

	gmtime_r(&now, &tm);
	strftime(ver, sizeof ver, "%Y%m%d.%H%M%S", &tm);
	return apk_atomize_dup(&db->atoms, APK_BLOB_STR(ver));
}

static int add_main(void *ctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	struct apk_out *out = &ac->out;
	struct apk_database *db = ac->db;
	struct add_ctx *actx = (struct add_ctx *) ctx;
	struct apk_package_tmpl virtpkg;
	struct apk_dependency virtdep;
	struct apk_dependency_array *world;
	char **parg;
	int r = 0;

	apk_pkgtmpl_init(&virtpkg);
	apk_dependency_array_init(&world);
	apk_dependency_array_copy(&world, db->world);

	if (actx->virtpkg) {
		apk_blob_t b = APK_BLOB_STR(actx->virtpkg);
		apk_blob_pull_dep(&b, db, &virtdep);

		if (APK_BLOB_IS_NULL(b) || apk_dep_conflict(&virtdep) ||
		    (virtdep.name->name[0] != '.' && non_repository_check(db)) ||
		    virtdep.broken)
			goto bad_spec;

		switch (virtdep.op) {
		case APK_DEPMASK_ANY:
			if (virtdep.version != &apk_atom_null) goto bad_spec;
			virtdep.op = APK_VERSION_EQUAL;
			virtdep.version = generate_version(db);
			break;
		case APK_VERSION_EQUAL:
			if (virtdep.version == &apk_atom_null) goto bad_spec;
			break;
		default:
		bad_spec:
			apk_err(out, "%s: bad package specifier", actx->virtpkg);
			return -1;
		}

		create_virtual_package(&virtpkg, db, &virtdep);
		if (apk_array_len(args) == 0) apk_warn(out, "creating empty virtual package");
	}

	foreach_array_item(parg, args) {
		struct apk_dependency dep;

		if (strstr(*parg, ".apk") != NULL) {
			struct apk_package *pkg = NULL;

			if (non_repository_check(db))
				return -1;

			r = apk_pkg_read(db, *parg, &pkg, TRUE);
			if (r != 0) {
				apk_err(out, "%s: %s", *parg, apk_error_str(r));
				return -1;
			}
			apk_dep_from_pkg(&dep, db, pkg);
		} else {
			apk_blob_t b = APK_BLOB_STR(*parg);

			apk_blob_pull_dep(&b, db, &dep);
			if (APK_BLOB_IS_NULL(b) || b.len > 0 || dep.broken || (actx->virtpkg && dep.repository_tag)) {
				apk_err(out, "'%s' is not a valid %s dependency, format is %s",
					*parg,
					actx->virtpkg ? "package" : "world",
					actx->virtpkg ? "name([<>~=]version)" : "name(@tag)([<>~=]version)");
				return -1;
			}
		}

		if (actx->virtpkg) {
			apk_deps_add(&virtpkg.pkg.depends, &dep);
		} else {
			apk_deps_add(&world, &dep);
			apk_solver_set_name_flags(dep.name,
						  actx->solver_flags,
						  actx->solver_flags);
		}
	}
	if (actx->virtpkg) {
		apk_db_pkg_add(db, &virtpkg);
		apk_deps_add(&world, &virtdep);
		apk_solver_set_name_flags(virtdep.name,
					  actx->solver_flags,
					  actx->solver_flags);
	}

	r = apk_solver_commit(db, 0, world);
	apk_dependency_array_free(&world);
	apk_pkgtmpl_free(&virtpkg);

	return r;
}

static struct apk_applet apk_add = {
	.name = "add",
	.open_flags = APK_OPENF_WRITE,
	.remove_empty_arguments = 1,
	.context_size = sizeof(struct add_ctx),
	.optgroups = { &optgroup_global, &optgroup_commit, &optgroup_applet },
	.main = add_main,
};

APK_DEFINE_APPLET(apk_add);
