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

#define APK_OPTAPPLET		"\x00"
#define APK_OPTGROUP(_name)	_name "\x00"
#define APK_OPT1n(_opt)		       "\xf0" _opt "\x00"
#define APK_OPT1R(_opt)		"\xaf" "\xf0" _opt "\x00"
#define APK_OPT2n(_opt, _short)	       _short _opt "\x00"
#define APK_OPT2R(_opt, _short)	"\xaf" _short _opt "\x00"

struct apk_option_group {
	const char *desc;
	int (*parse)(void *ctx, struct apk_db_options *dbopts,
		     int opt, const char *optarg);
};

struct apk_applet {
	struct list_head node;

	const char *name;
	const struct apk_option_group *optgroups[4];

	unsigned int open_flags, forced_flags, forced_force;
	int context_size;

	int (*main)(void *ctx, struct apk_database *db, struct apk_string_array *args);
};

extern const struct apk_option_group optgroup_global, optgroup_commit;

void apk_help(struct apk_applet *applet);
void apk_applet_register(struct apk_applet *);
typedef void (*apk_init_func_t)(void);

#define APK_DEFINE_APPLET(x) \
static void __register_##x(void) { apk_applet_register(&x); } \
static apk_init_func_t __regfunc_##x __attribute__((__section__("initapplets"))) __attribute((used)) = __register_##x;

#endif
