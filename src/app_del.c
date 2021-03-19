/* app_del.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include "apk_applet.h"
#include "apk_database.h"
#include "apk_print.h"
#include "apk_solver.h"

struct del_ctx {
	int recursive_delete : 1;
	struct apk_dependency_array *world;
	int errors;
};

#define DEL_OPTIONS(OPT) \
	OPT(OPT_DEL_redepends,	APK_OPT_SH("r") "rdepends")

APK_OPT_APPLET(option_desc, DEL_OPTIONS);

static int option_parse_applet(void *pctx, struct apk_ctx *ac, int opt, const char *optarg)
{
	struct del_ctx *ctx = (struct del_ctx *) pctx;

	switch (opt) {
	case OPT_DEL_redepends:
		ctx->recursive_delete = 1;
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

struct not_deleted_ctx {
	struct apk_out *out;
	struct apk_indent indent;
	struct apk_name *name;
	unsigned int matches;
	int header;
};

static inline int name_in_world(struct apk_name *n)
{
	return n->state_int == 1;
}

static void print_not_deleted_pkg(struct apk_package *pkg0, struct apk_dependency *dep0,
				  struct apk_package *pkg, void *pctx)
{
	struct not_deleted_ctx *ctx = (struct not_deleted_ctx *) pctx;
	struct apk_out *out = ctx->out;
	struct apk_dependency *d;
	struct apk_provider *p;

	if (!ctx->header) {
		apk_msg(out, "World updated, but the following packages are not removed due to:");
		ctx->header = 1;
	}
	if (!ctx->indent.indent) {
		ctx->indent.x = printf("  %s:", ctx->name->name);
		ctx->indent.indent = ctx->indent.x + 1;
	}

	if (name_in_world(pkg0->name)) {
		apk_print_indented(&ctx->indent, APK_BLOB_STR(pkg0->name->name));
	}
	foreach_array_item(d, pkg0->provides) {
		if (!name_in_world(d->name)) continue;
		apk_print_indented(&ctx->indent, APK_BLOB_STR(d->name->name));
	}

	apk_pkg_foreach_reverse_dependency(pkg0, ctx->matches, print_not_deleted_pkg, pctx);
	foreach_array_item(d, pkg0->install_if) {
		foreach_array_item(p, d->name->providers) {
			if (!p->pkg->marked) continue;
			if (apk_pkg_match_genid(p->pkg, ctx->matches)) continue;
			print_not_deleted_pkg(p->pkg, NULL, NULL, pctx);
		}
	}
}

static void print_not_deleted_name(struct apk_database *db, const char *match,
				   struct apk_name *name, void *pctx)
{
	struct apk_out *out = &db->ctx->out;
	struct not_deleted_ctx *ctx = (struct not_deleted_ctx *) pctx;
	struct apk_provider *p;

	ctx->indent = (struct apk_indent) { .out = out };
	ctx->name = name;
	ctx->matches = apk_foreach_genid() | APK_FOREACH_MARKED | APK_DEP_SATISFIES;
	foreach_array_item(p, name->providers)
		if (p->pkg->marked)
			print_not_deleted_pkg(p->pkg, NULL, NULL, ctx);
	if (ctx->indent.indent)
		printf("\n");
}

static void delete_pkg(struct apk_package *pkg0, struct apk_dependency *dep0,
		       struct apk_package *pkg, void *pctx)
{
	struct del_ctx *ctx = (struct del_ctx *) pctx;

	apk_deps_del(&ctx->world, pkg0->name);
	if (ctx->recursive_delete)
		apk_pkg_foreach_reverse_dependency(
			pkg0, APK_FOREACH_INSTALLED | APK_DEP_SATISFIES,
			delete_pkg, pctx);
}

static void delete_name(struct apk_database *db, const char *match,
			struct apk_name *name, void *pctx)
{
	struct apk_out *out = &db->ctx->out;
	struct del_ctx *ctx = (struct del_ctx *) pctx;
	struct apk_package *pkg;

	if (!name) {
		apk_err(out, "No such package: %s", match);
		ctx->errors++;
		return;
	}

	pkg = apk_pkg_get_installed(name);
	if (pkg != NULL)
		delete_pkg(pkg, NULL, NULL, pctx);
	else
		apk_deps_del(&ctx->world, name);
}

static int del_main(void *pctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	struct apk_database *db = ac->db;
	struct del_ctx *ctx = (struct del_ctx *) pctx;
	struct not_deleted_ctx ndctx = { .out = &db->ctx->out };
	struct apk_changeset changeset = {};
	struct apk_change *change;
	struct apk_dependency *d;
	int r = 0;

	apk_dependency_array_copy(&ctx->world, db->world);
	apk_name_foreach_matching(db, args, apk_foreach_genid(), delete_name, ctx);
	if (ctx->errors) return ctx->errors;

	r = apk_solver_solve(db, 0, ctx->world, &changeset);
	if (r == 0) {
		/* check for non-deleted package names */
		foreach_array_item(change, changeset.changes)
			if (change->new_pkg != NULL)
				change->new_pkg->marked = 1;
		foreach_array_item(d, ctx->world)
			d->name->state_int = 1;
		apk_name_foreach_matching(
			db, args,
			apk_foreach_genid() | APK_FOREACH_MARKED | APK_DEP_SATISFIES,
			print_not_deleted_name, &ndctx);
		if (ndctx.header)
			printf("\n");

		r = apk_solver_commit_changeset(db, &changeset, ctx->world);
	} else {
		apk_solver_print_errors(db, &changeset, ctx->world);
	}
	apk_change_array_free(&changeset.changes);
	apk_dependency_array_free(&ctx->world);

	return r;
}

static struct apk_applet apk_del = {
	.name = "del",
	.open_flags = APK_OPENF_WRITE | APK_OPENF_NO_AUTOUPDATE,
	.context_size = sizeof(struct del_ctx),
	.optgroups = { &optgroup_global, &optgroup_commit, &optgroup_applet },
	.main = del_main,
};

APK_DEFINE_APPLET(apk_del);
