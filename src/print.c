/* print.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "apk_defines.h"
#include "apk_print.h"

int apk_progress_fd;
static int apk_screen_width = 0;
static int apk_progress_force = 1;
static const char *apk_progress_char = "#";
static const char *apk_size_units[] = {"B", "KiB", "MiB", "GiB", "TiB"};

void apk_reset_screen_width(void)
{
	apk_screen_width = 0;
	apk_progress_force = 1;
}

int apk_get_screen_width(void)
{
	struct winsize w;
	const char *lang;
	const char *progress_char;

	if (apk_screen_width == 0) {
		apk_screen_width = 50;
		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 &&
		    w.ws_col > 25)
			apk_screen_width = w.ws_col;
	}

	lang = getenv("LANG");
	if (lang != NULL && strstr(lang, "UTF-8") != NULL)
		apk_progress_char = "\u2588";

	if ((progress_char = getenv("APK_PROGRESS_CHAR")) != NULL)
		apk_progress_char = progress_char;

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
	case EAPKDBFORMAT:
		return "database file format error";
	case EAPKCACHE:
		return "cache not available";
	case EAPKCRYPTO:
		return "cryptocraphic library error";
	default:
		return strerror(error);
	}
}

int apk_exit_status_str(int status, char *buf, size_t sz)
{
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
		return 0;
	if (WIFEXITED(status))
		return snprintf(buf, sz, "exited with error %d", WEXITSTATUS(status));
	if (WIFSIGNALED(status))
		return snprintf(buf, sz, "killed by signal %d", WTERMSIG(status));
	if (WIFSTOPPED(status))
		return snprintf(buf, sz, "stopped by signal %d", WSTOPSIG(status));
	if (WIFCONTINUED(status))
		return snprintf(buf, sz, "continued");
	return snprintf(buf, sz, "status unknown %x", status);
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

void apk_print_progress(size_t done, size_t total)
{
	static size_t last_done = 0;
	static int last_bar = 0, last_percent = 0;
	int bar_width;
	int bar = 0;
	char buf[64]; /* enough for petabytes... */
	int i, percent = 0;

	if (last_done == done && !apk_progress_force)
		return;

	if (apk_progress_fd != 0) {
		i = snprintf(buf, sizeof(buf), "%zu/%zu\n", done, total);
		write(apk_progress_fd, buf, i);
	}
	last_done = done;

	if (!(apk_flags & APK_PROGRESS))
		return;

	bar_width = apk_get_screen_width() - 6;
	if (total > 0) {
		bar = muldiv(bar_width, done, total);
		percent = muldiv(100, done, total);
	}

	if (bar  == last_bar && percent == last_percent && !apk_progress_force)
		return;

	last_bar = bar;
	last_percent = percent;
	apk_progress_force = 0;

	fprintf(stdout, "\e7%3i%% ", percent);

	for (i = 0; i < bar; i++)
		fputs(apk_progress_char, stdout);
	for (; i < bar_width; i++)
		fputc(' ', stdout);

	fflush(stdout);
	fputs("\e8\e[0K", stdout);
}

void apk_print_indented_init(struct apk_indent *i, int err)
{
	*i = (struct apk_indent) {
		.f = err ? stderr : stdout,
		.width = apk_get_screen_width(),
	};
	apk_progress_force = 1;
}

void apk_print_indented_line(struct apk_indent *i, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	vfprintf(i->f, fmt, va);
	va_end(va);
	i->x = i->indent = 0;
}

void apk_print_indented_group(struct apk_indent *i, int indent, const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	i->x = vfprintf(i->f, fmt, va);
	i->indent = indent ?: (i->x + 1);
	if (fmt[strlen(fmt)-1] == '\n') i->x = 0;
	va_end(va);
}

void apk_print_indented_end(struct apk_indent *i)
{
	if (i->x) {
		fprintf(i->f, "\n");
		i->x = i->indent = 0;
	}
}

int apk_print_indented(struct apk_indent *i, apk_blob_t blob)
{
	if (i->x <= i->indent)
		i->x += fprintf(i->f, "%*s" BLOB_FMT, i->indent - i->x, "", BLOB_PRINTF(blob));
	else if (i->x + blob.len + 1 >= i->width)
		i->x = fprintf(i->f, "\n%*s" BLOB_FMT, i->indent, "", BLOB_PRINTF(blob)) - 1;
	else
		i->x += fprintf(i->f, " " BLOB_FMT, BLOB_PRINTF(blob));
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
