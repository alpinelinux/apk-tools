/* apk_print.h - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef APK_PRINT_H
#define APK_PRINT_H

#include "apk_blob.h"

#define apk_error(args...)	do { apk_log_err("ERROR: ", args); } while (0)
#define apk_warning(args...)	do { if (apk_verbosity > 0) { apk_log_err("WARNING: ", args); } } while (0)
#define apk_message(args...)	do { if (apk_verbosity > 0) { apk_log(NULL, args); } } while (0)

extern int apk_progress_fd;

void apk_log(const char *prefix, const char *format, ...);
void apk_log_err(const char *prefix, const char *format, ...);
const char *apk_error_str(int error);

void apk_reset_screen_width(void);
int apk_get_screen_width(void);
const char *apk_get_human_size(off_t size, off_t *dest);

struct apk_indent {
	int x;
	int indent;
};

void apk_print_progress(size_t done, size_t total);
int  apk_print_indented(struct apk_indent *i, apk_blob_t blob);
void apk_print_indented_words(struct apk_indent *i, const char *text);
void apk_print_indented_fmt(struct apk_indent *i, const char *fmt, ...);

#endif
