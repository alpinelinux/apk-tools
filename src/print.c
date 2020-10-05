/* print.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>

#include "apk_defines.h"
#include "apk_print.h"

static int apk_screen_width = 0;
static int apk_progress_force = 1;
static const char *apk_size_units[] = {"B", "KiB", "MiB", "GiB", "TiB"};

void apk_reset_screen_width(void)
{
	apk_screen_width = 0;
	apk_progress_force = 1;
}

int apk_get_screen_width(void)
{
	struct winsize w;

	if (apk_screen_width == 0) {
		apk_screen_width = 50;
		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 &&
		    w.ws_col > 25)
			apk_screen_width = w.ws_col;
	}

	return apk_screen_width;
}

const char *apk_get_human_size(off_t size, off_t *dest)
{
	size_t i;
	off_t s;

	assert(size >= 0);

	for (i = 0, s = size; s >= 10000 &&
	     i < ARRAY_SIZE(apk_size_units); i++)
		s /= 1024;

	if (dest) *dest = s;
	return apk_size_units[min(i, ARRAY_SIZE(apk_size_units) - 1)];
}

void apk_print_progress(struct apk_progress *p, size_t done, size_t total)
{
	int bar_width;
	int bar = 0;
	char buf[64]; /* enough for petabytes... */
	int i, percent = 0;
	FILE *out = p->out;

	if (p->last_done == done && !apk_progress_force)
		return;

	if (p->fd != 0) {
		i = snprintf(buf, sizeof(buf), "%zu/%zu\n", done, total);
		write(p->fd, buf, i);
	}
	p->last_done = done;

	if (!out) return;

	bar_width = apk_get_screen_width() - 6;
	if (total > 0) {
		bar = muldiv(bar_width, done, total);
		percent = muldiv(100, done, total);
	}

	if (bar == p->last_bar && percent == p->last_percent && !apk_progress_force)
		return;

	p->last_bar = bar;
	p->last_percent = percent;
	apk_progress_force = 0;

	fprintf(out, "\e7%3i%% ", percent);

	for (i = 0; i < bar; i++)
		fputs(p->progress_char, out);
	for (; i < bar_width; i++)
		fputc(' ', out);

	fflush(out);
	fputs("\e8\e[0K", out);
}

int apk_print_indented(struct apk_indent *i, apk_blob_t blob)
{
	if (i->x <= i->indent)
		i->x += printf("%*s" BLOB_FMT, i->indent - i->x, "", BLOB_PRINTF(blob));
	else if (i->x + blob.len + 1 >= apk_get_screen_width())
		i->x = printf("\n%*s" BLOB_FMT, i->indent, "", BLOB_PRINTF(blob)) - 1;
	else
		i->x += printf(" " BLOB_FMT, BLOB_PRINTF(blob));
	apk_progress_force = 1;
	return 0;
}

void apk_print_indented_words(struct apk_indent *i, const char *text)
{
	apk_blob_for_each_segment(APK_BLOB_STR(text), " ",
		(apk_blob_cb) apk_print_indented, i);
}

void apk_print_indented_fmt(struct apk_indent *i, const char *fmt, ...)
{
	char tmp[256];
	size_t n;
	va_list va;

	va_start(va, fmt);
	n = vsnprintf(tmp, sizeof(tmp), fmt, va);
	apk_print_indented(i, APK_BLOB_PTR_LEN(tmp, n));
	va_end(va);
}

const char *apk_error_str(int error)
{
	if (error < 0)
		error = -error;
	switch (error) {
	case ENOKEY:
		return "UNTRUSTED signature";
	case EKEYREJECTED:
		return "BAD signature";
	case EIO:
		return "IO ERROR";
	case EBADMSG:
		return "BAD archive";
	case ENOMSG:
		return "archive does not contain expected data";
	case ENOPKG:
		return "could not find a repo which provides this package (check repositories file and run 'apk update')";
	case ECONNABORTED:
		return "network connection aborted";
	case ECONNREFUSED:
		return "could not connect to server (check repositories file)";
	case ENETUNREACH:
		return "network error (check Internet connection and firewall)";
	case ENXIO:
		return "DNS lookup error";
	case EREMOTEIO:
		return "remote server returned error (try 'apk update')";
	case ETIMEDOUT:
		return "operation timed out";
	case EAGAIN:
		return "temporary error (try again later)";
	case EAPKBADURL:
		return "invalid URL (check your repositories file)";
	case EAPKSTALEINDEX:
		return "package mentioned in index not found (try 'apk update')";
	case EAPKFORMAT:
		return "package file format error";
	case EAPKDEPFORMAT:
		return "package dependency format error";
	default:
		return strerror(error);
	}
}

static void log_internal(FILE *dest, const char *prefix, const char *format, va_list va)
{
	if (dest != stdout)
		fflush(stdout);
	if (prefix != NULL)
		fprintf(dest, "%s", prefix);
	vfprintf(dest, format, va);
	fprintf(dest, "\n");
	fflush(dest);
	apk_progress_force = 1;
}

void apk_log(const char *prefix, const char *format, ...)
{
	va_list va;
	va_start(va, format);
	log_internal(stdout, prefix, format, va);
	va_end(va);
}

void apk_log_err(const char *prefix, const char *format, ...)
{
	va_list va;
	va_start(va, format);
	log_internal(stderr, prefix, format, va);
	va_end(va);
}

void apk_url_parse(struct apk_url_print *urlp, const char *url)
{
	const char *authority, *path_or_host, *pw;

	*urlp = (struct apk_url_print) {
		.url = "",
		.pwmask = "",
		.url_or_host = url,
	};

	if (!(authority = strstr(url, "://"))) return;
	authority += 3;
	path_or_host = strpbrk(authority, "/@");
	if (!path_or_host || *path_or_host == '/') return;
	pw = strpbrk(authority, "@:");
	if (!pw || *pw == '@') return;
	*urlp = (struct apk_url_print) {
		.url = url,
		.pwmask = "*",
		.url_or_host = path_or_host,
		.len_before_pw = pw - url + 1,
	};
}
