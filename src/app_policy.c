/* app_policy.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2013 Timo Teräs <timo.teras@iki.fi>
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

static int print_policy(struct apk_database *db, const char *match, struct apk_name *name, void *ctx)
{
	struct apk_out *out = &db->ctx->out;
	struct apk_provider *p;
	struct apk_repository *repo;
	int i, j, num = 0;

	if (!name) return 0;

/*
zlib1g policy:
  2.0:
    @testing http://nl.alpinelinux.org/alpine/edge/testing
  1.7:
    @edge http://nl.alpinelinux.org/alpine/edge/main
  1.2.3.5 (upgradeable):
    http://nl.alpinelinux.org/alpine/v2.6/main
  1.2.3.4 (installed):
    /media/cdrom/...
    http://nl.alpinelinux.org/alpine/v2.5/main
  1.1:
    http://nl.alpinelinux.org/alpine/v2.4/main
*/
	apk_name_sorted_providers(name);
	foreach_array_item(p, name->providers) {
		if (p->pkg->name != name) continue;
		if (num++ == 0) apk_out(out, "%s policy:", name->name);
		apk_out(out, "  " BLOB_FMT ":", BLOB_PRINTF(*p->version));
		if (p->pkg->ipkg)
			apk_out(out, "    %s/installed", apk_db_layer_name(p->pkg->layer));
		for (i = 0; i < db->num_repos; i++) {
			repo = &db->repos[i];
			if (!(BIT(i) & p->pkg->repos))
				continue;
			for (j = 0; j < db->num_repo_tags; j++) {
				if (db->repo_tags[j].allowed_repos & p->pkg->repos)
					apk_out(out, "    "BLOB_FMT"%s%s",
						BLOB_PRINTF(db->repo_tags[j].tag),
						j == 0 ? "" : " ",
						repo->url);
			}
		}
	}
	return 0;
}

static int policy_main(void *ctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	if (apk_array_len(args) == 0) return 0;
	apk_db_foreach_sorted_name(ac->db, args, print_policy, NULL);
	return 0;
}

static struct apk_applet apk_policy = {
	.name = "policy",
	.open_flags = APK_OPENF_READ | APK_OPENF_ALLOW_ARCH,
	.optgroups = { &optgroup_global, &optgroup_source },
	.main = policy_main,
};

APK_DEFINE_APPLET(apk_policy);


