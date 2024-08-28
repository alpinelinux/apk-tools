/* app_dot.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include <fnmatch.h>

#include "apk_applet.h"
#include "apk_database.h"
#include "apk_print.h"

#define S_EVALUATED	-1
#define S_EVALUATING	-2

struct dot_ctx {
	unsigned short not_empty : 1;
	unsigned short errors_only : 1;
	unsigned short installed_only : 1;
};

#define DOT_OPTIONS(OPT) \
	OPT(OPT_DOT_errors,	"errors") \
	OPT(OPT_DOT_installed,	"installed")

APK_OPT_APPLET(option_desc, DOT_OPTIONS);

static int option_parse_applet(void *pctx, struct apk_ctx *ac, int opt, const char *optarg)
{
	struct dot_ctx *ctx = (struct dot_ctx *) pctx;

	switch (opt) {
	case OPT_DOT_errors:
		ctx->errors_only = 1;
		break;
	case OPT_DOT_installed:
		ctx->installed_only = 1;
		ac->open_flags &= ~APK_OPENF_NO_INSTALLED;
		ac->open_flags |= APK_OPENF_NO_SYS_REPOS;
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

static void start_graph(struct dot_ctx *ctx)
{
	if (ctx->not_empty)
		return;
	ctx->not_empty = 1;

	printf( "digraph \"apkindex\" {\n"
		"  rankdir=LR;\n"
		"  node [shape=box];\n");
}

static void dump_error_name(struct dot_ctx *ctx, struct apk_name *name)
{
	if (name->state_int)
		return;
	name->state_int = 1;
	start_graph(ctx);
	printf("  \"%s\" [style=dashed, color=red, fontcolor=red, shape=octagon];\n",
		name->name);
}

static void dump_broken_deps(struct dot_ctx *ctx, struct apk_package *pkg, const char *kind, struct apk_dependency *dep)
{
	if (!dep->broken) return;

	dump_error_name(ctx, dep->name);
	printf("  \"" PKG_VER_FMT "\" -> \"%s\" [arrowhead=%s,style=dashed,color=red,fontcolor=red,label=\"" DEP_FMT "\"];\n",
		PKG_VER_PRINTF(pkg), dep->name->name,
		kind,
		DEP_PRINTF(dep));
}

static int dump_pkg(struct dot_ctx *ctx, struct apk_package *pkg)
{
	struct apk_dependency *dep;
	struct apk_provider *p0;
	int r, ret = 0;

	if (ctx->installed_only && pkg->ipkg == NULL)
		return 0;

	if (pkg->state_int == S_EVALUATED)
		return 0;

	if (pkg->state_int <= S_EVALUATING) {
		pkg->state_int--;
		return 1;
	}

	pkg->state_int = S_EVALUATING;
	foreach_array_item(dep, pkg->depends) {
		struct apk_name *name = dep->name;

		dump_broken_deps(ctx, pkg, "normal", dep);

		if (dep->op & APK_VERSION_CONFLICT)
			continue;

		if (apk_array_len(name->providers) == 0) {
			dump_error_name(ctx, name);
			printf("  \"" PKG_VER_FMT "\" -> \"%s\" [color=red];\n",
				PKG_VER_PRINTF(pkg), name->name);
			continue;
		}

		foreach_array_item(p0, name->providers) {
			if (ctx->installed_only && p0->pkg->ipkg == NULL)
				continue;
			if (!apk_dep_is_provided(pkg, dep, p0))
				continue;

			r = dump_pkg(ctx, p0->pkg);
			ret += r;
			if (r || (!ctx->errors_only)) {
				start_graph(ctx);

				printf("  \"" PKG_VER_FMT "\" -> \"" PKG_VER_FMT "\"[",
					PKG_VER_PRINTF(pkg),
					PKG_VER_PRINTF(p0->pkg));
				if (r)
					printf("color=red,");
				if (p0->pkg->name != dep->name)
					printf("arrowhead=inv,label=\"%s\",", dep->name->name);
				printf("];\n");
			}
		}
	}
	foreach_array_item(dep, pkg->provides) dump_broken_deps(ctx, pkg, "inv", dep);
	foreach_array_item(dep, pkg->install_if) dump_broken_deps(ctx, pkg, "diamond", dep);
	ret -= S_EVALUATING - pkg->state_int;
	pkg->state_int = S_EVALUATED;

	return ret;
}

static int dump(struct apk_database *db, const char *match, struct apk_name *name, void *pctx)
{
	struct dot_ctx *ctx = pctx;
	struct apk_provider *p;

	if (!name) return 0;

	apk_name_sorted_providers(name);
	foreach_array_item(p, name->providers)
		dump_pkg(ctx, p->pkg);
	return 0;
}

static int dot_main(void *pctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	struct apk_database *db = ac->db;
	struct dot_ctx *ctx = (struct dot_ctx *) pctx;

	apk_db_foreach_matching_name(db, args, dump, pctx);

	if (!ctx->not_empty)
		return 1;

	printf("}\n");
	return 0;
}

static struct apk_applet apk_dot = {
	.name = "dot",
	.open_flags = APK_OPENF_READ | APK_OPENF_NO_STATE | APK_OPENF_ALLOW_ARCH,
	.remove_empty_arguments = 1,
	.context_size = sizeof(struct dot_ctx),
	.optgroups = { &optgroup_global, &optgroup_source, &optgroup_applet },
	.main = dot_main,
};

APK_DEFINE_APPLET(apk_dot);
