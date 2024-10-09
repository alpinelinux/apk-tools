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

#include <stdio.h>
#include "apk_blob.h"

#define APK_EXIT_STATUS_MAX_SIZE	128

const char *apk_error_str(int error);
int apk_exit_status_str(int status, char *buf, size_t sz);
int apk_get_human_size_unit(apk_blob_t b);
const char *apk_get_human_size(off_t size, off_t *dest);
const char *apk_last_path_segment(const char *);

struct apk_url_print {
	const char *url;
	const char *pwmask;
	const char *url_or_host;
	size_t len_before_pw;
};

void apk_url_parse(struct apk_url_print *, const char *);

#define URL_FMT			"%.*s%s%s"
#define URL_PRINTF(u)		(int)u.len_before_pw, u.url, u.pwmask, u.url_or_host

struct apk_out {
	int verbosity;
	unsigned int width, last_change;
	FILE *out, *err, *log;
};

static inline int apk_out_verbosity(struct apk_out *out) { return out->verbosity; }

// Pass this as the prefix to skip logging to the console (but still write to
// the log file).
#define APK_OUT_LOG_ONLY ((const char*)-1)

#define apk_err(out, args...)	do { apk_out_fmt(out, "ERROR: ", args); } while (0)
#define apk_out(out, args...)	do { apk_out_fmt(out, NULL, args); } while (0)
#define apk_warn(out, args...)	do { if (apk_out_verbosity(out) >= 0) { apk_out_fmt(out, "WARNING: ", args); } } while (0)
#define apk_notice(out, args...) do { if (apk_out_verbosity(out) >= 0) { apk_out_fmt(out, "", args); } } while (0)
#define apk_msg(out, args...)	do { if (apk_out_verbosity(out) >= 1) { apk_out_fmt(out, NULL, args); } } while (0)
#define apk_dbg(out, args...)	do { if (apk_out_verbosity(out) >= 2) { apk_out_fmt(out, NULL, args); } } while (0)
#define apk_dbg2(out, args...)	do { if (apk_out_verbosity(out) >= 3) { apk_out_fmt(out, NULL, args); } } while (0)

void apk_out_reset(struct apk_out *);
void apk_out_fmt(struct apk_out *, const char *prefix, const char *format, ...)
	__attribute__ ((format (printf, 3, 4)));
void apk_out_log_argv(struct apk_out *, char **argv);

struct apk_progress {
	struct apk_out *out;
	int fd, last_bar, last_percent;
	unsigned int last_out_change;
	size_t last_done;
	const char *progress_char;
};

void apk_print_progress(struct apk_progress *p, size_t done, size_t total);

struct apk_indent {
	FILE *f;
	unsigned int x, indent, width;
};

void apk_print_indented_init(struct apk_indent *i, struct apk_out *out, int err);
void apk_print_indented_line(struct apk_indent *i, const char *fmt, ...);
void apk_print_indented_group(struct apk_indent *i, int indent, const char *fmt, ...);
void apk_print_indented_end(struct apk_indent *i);
int  apk_print_indented(struct apk_indent *i, apk_blob_t blob);
void apk_print_indented_words(struct apk_indent *i, const char *text);
void apk_print_indented_fmt(struct apk_indent *i, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

#endif
