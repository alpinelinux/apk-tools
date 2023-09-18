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

#define APK_EXIT_STATUS_MAX_SIZE	128

struct apk_url_print {
	const char *url;
	const char *pwmask;
	const char *url_or_host;
	size_t len_before_pw;
};

void apk_url_parse(struct apk_url_print *, const char *);

#define URL_FMT			"%.*s%s%s"
#define URL_PRINTF(u)		(int)u.len_before_pw, u.url, u.pwmask, u.url_or_host

#define apk_error(args...)	do { apk_log_err("ERROR: ", args); } while (0)
#define apk_warning(args...)	do { if (apk_verbosity > 0) { apk_log_err("WARNING: ", args); } } while (0)
#define apk_message(args...)	do { if (apk_verbosity > 0) { apk_log(NULL, args); } } while (0)

extern int apk_progress_fd;

void apk_log(const char *prefix, const char *format, ...)
	__attribute__ ((format (printf, 2, 3)));
void apk_log_err(const char *prefix, const char *format, ...)
	__attribute__ ((format (printf, 2, 3)));
const char *apk_error_str(int error);
int apk_exit_status_str(int status, char *buf, size_t sz);

void apk_reset_screen_width(void);
int apk_get_screen_width(void);
const char *apk_get_human_size(off_t size, off_t *dest);

struct apk_indent {
	FILE *f;
	unsigned int x, indent, width;
};

void apk_print_progress(size_t done, size_t total);

void apk_print_indented_init(struct apk_indent *i, int err);
void apk_print_indented_line(struct apk_indent *i, const char *fmt, ...);
void apk_print_indented_group(struct apk_indent *i, int indent, const char *fmt, ...);
void apk_print_indented_end(struct apk_indent *i);
int  apk_print_indented(struct apk_indent *i, apk_blob_t blob);
void apk_print_indented_words(struct apk_indent *i, const char *text);
void apk_print_indented_fmt(struct apk_indent *i, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

#endif
