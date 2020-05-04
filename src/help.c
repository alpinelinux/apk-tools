/* help.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2020 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation. See http://www.gnu.org/ for details.
 */

#include <zlib.h>
#include "apk_applet.h"
#include "apk_print.h"

static int is_group(struct apk_applet *applet, const char *topic)
{
	if (!applet) return strcasecmp(topic, "apk") == 0;
	if (strcasecmp(topic, applet->name) == 0) return 1;
	for (int i = 0; applet->optgroups[i] && i < ARRAY_SIZE(applet->optgroups); i++)
		if (strcasecmp(applet->optgroups[i]->desc, topic) == 0) return 1;
	return 0;
}

void apk_help(struct apk_applet *applet)
{
#include "help.h"

	char buf[uncompressed_help_size], *ptr, *msg;
	unsigned long len = sizeof buf;
	int num = 0;

	uncompress((unsigned char*) buf, &len, compressed_help, sizeof compressed_help);
	for (ptr = buf; *ptr && ptr < &buf[len]; ptr = msg + strlen(msg) + 1) {
		msg = ptr + strlen(ptr) + 1;

		if (is_group(applet, ptr)) {
			fputc('\n', stdout);
			fwrite(msg, strlen(msg), 1, stdout);
			num++;
		}
	}
	if (num == 0) apk_error("Help not found");
}
