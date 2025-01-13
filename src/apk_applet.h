/* apk_applet.h - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef APK_APPLET_H
#define APK_APPLET_H

#include <errno.h>
#include <getopt.h>
#include "apk_defines.h"
#include "apk_database.h"

#if 0
#define APK_OPT1n(_opt)		       "\xf0" _opt "\x00"
#define APK_OPT1R(_opt)		"\xaf" "\xf0" _opt "\x00"
#define APK_OPT2n(_opt, _short)	       _short _opt "\x00"
#define APK_OPT2R(_opt, _short)	"\xaf" _short _opt "\x00"
#endif

#define __APK_OPTAPPLET		"\x00"
#define __APK_OPTGROUP(_name)	_name "\x00"
#define __APK_OPT_ENUM(_enum,__desc) _enum,
#define __APK_OPT_DESC(_enum,__desc) __desc "\x00"

#define APK_OPT_ARG		"\xaf"
#define APK_OPT_SH(x)		"\xf1" x
#define APK_OPT_S2(x)		"\xf2" x

#define APK_OPT_APPLET(var_name, init_macro) \
	enum { init_macro(__APK_OPT_ENUM) }; \
	static const char var_name[] = __APK_OPTAPPLET init_macro(__APK_OPT_DESC);

#define APK_OPT_GROUP(var_name, group_name, init_macro) \
	enum { init_macro(__APK_OPT_ENUM) }; \
	static const char var_name[] = __APK_OPTGROUP(group_name) init_macro(__APK_OPT_DESC);

#define APK_OPT_GROUP2(var_name, group_name, init_macro, init_macro2) \
	enum { init_macro(__APK_OPT_ENUM) init_macro2(__APK_OPT_ENUM) }; \
	static const char var_name[] = __APK_OPTGROUP(group_name) init_macro(__APK_OPT_DESC) init_macro2(__APK_OPT_DESC);

struct apk_option_group {
	const char *desc;
	int (*parse)(void *ctx, struct apk_db_options *dbopts,
		     int opt, const char *optarg);
};

struct apk_applet {
	struct list_head node;

	const char *name;
	const struct apk_option_group *optgroups[4];

	unsigned int open_flags;
	unsigned int remove_empty_arguments : 1;
	unsigned int update_cache : 1;
	int context_size;

	int (*main)(void *ctx, struct apk_database *db, struct apk_string_array *args);
};

extern const struct apk_option_group optgroup_global, optgroup_commit, optgroup_source;

void apk_applet_register(struct apk_applet *);
struct apk_applet *apk_applet_find(const char *name);
void apk_applet_help(struct apk_applet *applet);

#define APK_DEFINE_APPLET(x) \
__attribute__((constructor)) static void __register_##x(void) { apk_applet_register(&x); }

#endif
