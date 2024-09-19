/* app_version.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include "apk_defines.h"
#include "apk_applet.h"
#include "apk_database.h"
#include "apk_version.h"
#include "apk_print.h"

struct ver_ctx {
	int (*action)(struct apk_database *db, struct apk_string_array *args);
	const char *limchars;
	unsigned int max_pkg_len;
	unsigned short all_tags : 1;
};

static int ver_indexes(struct apk_database *db, struct apk_string_array *args)
{
	struct apk_out *out = &db->ctx->out;
	struct apk_repository *repo;
	int i;

	for (i = 0; i < db->num_repos; i++) {
		repo = &db->repos[i];

		if (APK_BLOB_IS_NULL(repo->description))
			continue;

		apk_out(out, BLOB_FMT " [%s]",
			BLOB_PRINTF(repo->description),
			db->repos[i].url);
	}

	return 0;
}

static int ver_test(struct apk_database *db, struct apk_string_array *args)
{
	struct apk_out *out = &db->ctx->out;
	int r;

	if (apk_array_len(args) != 2) return 1;
	r = apk_version_compare(APK_BLOB_STR(args->item[0]), APK_BLOB_STR(args->item[1]));
	apk_out(out, "%s", apk_version_op_string(r));
	return 0;
}

static int ver_validate(struct apk_database *db, struct apk_string_array *args)
{
	struct apk_out *out = &db->ctx->out;
	char **parg;
	int errors = 0;

	foreach_array_item(parg, args) {
		if (!apk_version_validate(APK_BLOB_STR(*parg))) {
			apk_msg(out, "%s", *parg);
			errors++;
		}
	}
	return errors;
}

#define VERSION_OPTIONS(OPT) \
	OPT(OPT_VERSION_all,		APK_OPT_SH("a") "all") \
	OPT(OPT_VERSION_check,		APK_OPT_SH("c") "check") \
	OPT(OPT_VERSION_indexes,	APK_OPT_SH("I") "indexes") \
	OPT(OPT_VERSION_limit,		APK_OPT_ARG APK_OPT_SH("l") "limit") \
	OPT(OPT_VERSION_test,		APK_OPT_SH("t") "test")

APK_OPT_APPLET(option_desc, VERSION_OPTIONS);

static int option_parse_applet(void *ctx, struct apk_ctx *ac, int opt, const char *optarg)
{
	struct ver_ctx *ictx = (struct ver_ctx *) ctx;
	switch (opt) {
	case OPT_VERSION_all:
		ictx->all_tags = 1;
		break;
	case OPT_VERSION_check:
		ictx->action = ver_validate;
		ac->open_flags |= APK_OPENF_NO_STATE | APK_OPENF_NO_REPOS;
		break;
	case OPT_VERSION_indexes:
		ictx->action = ver_indexes;
		break;
	case OPT_VERSION_limit:
		ictx->limchars = optarg;
		break;
	case OPT_VERSION_test:
		ictx->action = ver_test;
		ac->open_flags |= APK_OPENF_NO_STATE | APK_OPENF_NO_REPOS;
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

struct ver_name_state {
	struct apk_package *installed, *latest;
	unsigned short tag, ver_result;
};

static struct ver_name_state *state_from_name(struct apk_name *name)
{
	static_assert(sizeof name->state_buf >= sizeof(struct ver_name_state), "buffer size mismatch");
	return (struct ver_name_state *) &name->state_buf[0];
}

static int ver_calculate_length(struct apk_database *db, const char *match, struct apk_name *name, void *pctx)
{
	struct ver_ctx *ctx = (struct ver_ctx *) pctx;
	struct apk_package *installed, *latest;
	struct apk_provider *p0;
	struct ver_name_state *ns;
	unsigned int latest_repos = 0;
	unsigned short tag, allowed_repos;
	const char *opstr;
	int i, r, len;

	if (!name) return 0;

	installed = latest = apk_pkg_get_installed(name);
	if (!installed) return 0;

	allowed_repos = db->repo_tags[installed->ipkg->repository_tag].allowed_repos;
	foreach_array_item(p0, name->providers) {
		struct apk_package *pkg0 = p0->pkg;
		if (pkg0->name != name || pkg0->repos == 0)
			continue;
		if (!(ctx->all_tags || (pkg0->repos & allowed_repos)))
			continue;
		r = apk_version_compare(*pkg0->version, *latest->version);
		switch (r) {
		case APK_VERSION_GREATER:
			latest = pkg0;
			latest_repos = pkg0->repos;
			break;
		case APK_VERSION_EQUAL:
			latest_repos |= pkg0->repos;
			break;
		}
	}

	ns = state_from_name(name);
	r = apk_version_compare(*installed->version, *latest->version);
	opstr = apk_version_op_string(r);
	if ((ctx->limchars != NULL) && (strchr(ctx->limchars, *opstr) == NULL))
		return 0;

	tag = APK_DEFAULT_REPOSITORY_TAG;
	for (i = 1; i < db->num_repo_tags; i++) {
		if (latest_repos & db->repo_tags[i].allowed_repos) {
			tag = i;
			break;
		}
	}

	*ns = (struct ver_name_state) {
		.installed = installed,
		.latest = latest,
		.tag = tag,
		.ver_result = r,
	};

	len = PKG_VER_STRLEN(installed);
	if (len > ctx->max_pkg_len) ctx->max_pkg_len = len;
	return 0;
}

static int ver_print_package_status(struct apk_database *db, const char *match, struct apk_name *name, void *pctx)
{
	struct apk_out *out = &db->ctx->out;
	struct ver_ctx *ctx = (struct ver_ctx *) pctx;
	struct ver_name_state *ns;

	if (!name) return 0;

	ns = state_from_name(name);
	if (!ns->installed) return 0;

	if (apk_out_verbosity(out) <= 0) {
		apk_out(out, "%s", name->name);
		return 0;
	}

	apk_out(out, PKG_VER_FMT "%*s %s " BLOB_FMT " " BLOB_FMT,
		PKG_VER_PRINTF(ns->installed),
		(int)(ctx->max_pkg_len - PKG_VER_STRLEN(ns->installed)), "",
		apk_version_op_string(ns->ver_result),
		BLOB_PRINTF(*ns->latest->version),
		BLOB_PRINTF(db->repo_tags[ns->tag].tag));
	return 0;
}

static int ver_main(void *pctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	struct apk_out *out = &ac->out;
	struct apk_database *db = ac->db;
	struct ver_ctx *ctx = (struct ver_ctx *) pctx;

	ctx->max_pkg_len = 39;
	if (ctx->limchars) {
		if (strlen(ctx->limchars) == 0)
			ctx->limchars = NULL;
	} else if (apk_array_len(args) == 0 && apk_out_verbosity(out) == 1) {
		ctx->limchars = "<";
	}

	if (ctx->action != NULL)
		return ctx->action(db, args);

	apk_db_foreach_matching_name(db, args, ver_calculate_length, ctx);

	apk_msg(out, "%*s   %s", -ctx->max_pkg_len, "Installed:", "Available:");
	apk_db_foreach_sorted_name(db, args, ver_print_package_status, ctx);
	return 0;
}

static struct apk_applet apk_ver = {
	.name = "version",
	.open_flags = APK_OPENF_READ,
	.context_size = sizeof(struct ver_ctx),
	.optgroups = { &optgroup_global, &optgroup_applet },
	.main = ver_main,
};

APK_DEFINE_APPLET(apk_ver);
