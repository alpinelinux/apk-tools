/* extract.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2008-2021 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "apk_applet.h"
#include "apk_print.h"
#include "apk_extract.h"

struct extract_ctx {
	const char *destination;
	unsigned int extract_flags;

	struct apk_extract_ctx ectx;
	struct apk_ctx *ac;
	int root_fd;
};


#define EXTRACT_OPTIONS(OPT) \
	OPT(OPT_EXTRACT_destination,	APK_OPT_ARG "destination") \
	OPT(OPT_EXTRACT_no_chown,	"no-chown")

APK_OPT_APPLET(option_desc, EXTRACT_OPTIONS);

static int option_parse_applet(void *pctx, struct apk_ctx *ac, int opt, const char *optarg)
{
	struct extract_ctx *ctx = (struct extract_ctx *) pctx;

	switch (opt) {
	case OPT_EXTRACT_destination:
		ctx->destination = optarg;
		break;
	case OPT_EXTRACT_no_chown:
		ctx->extract_flags |= APK_EXTRACTF_NO_CHOWN;
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

static int uvol_run(struct apk_ctx *ac, char *action, const char *volname, char *arg1, char *arg2)
{
	struct apk_out *out = &ac->out;
	pid_t pid;
	int r, status;
	char *argv[] = { (char*)apk_ctx_get_uvol(ac), action, (char*) volname, arg1, arg2, 0 };
	posix_spawn_file_actions_t act;

	posix_spawn_file_actions_init(&act);
	posix_spawn_file_actions_addclose(&act, STDIN_FILENO);
	r = posix_spawn(&pid, apk_ctx_get_uvol(ac), &act, 0, argv, environ);
	posix_spawn_file_actions_destroy(&act);
	if (r != 0) {
		apk_err(out, "%s: uvol exec error: %s", volname, apk_error_str(r));
		return r;
	}
	waitpid(pid, &status, 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		apk_err(out, "%s: uvol exited with error %d", volname, WEXITSTATUS(status));
		return -APKE_UVOL;
	}
	return 0;
}

static int uvol_extract(struct apk_ctx *ac, const char *volname, char *arg1, off_t sz, struct apk_istream *is)
{
	struct apk_out *out = &ac->out;
	struct apk_ostream *os;
	pid_t pid;
	int r, status, pipefds[2];
	char *argv[] = { (char*)apk_ctx_get_uvol(ac), "write", (char*) volname, arg1, 0 };
	posix_spawn_file_actions_t act;

	if (pipe2(pipefds, O_CLOEXEC) != 0) return -errno;

	posix_spawn_file_actions_init(&act);
	posix_spawn_file_actions_adddup2(&act, pipefds[0], STDIN_FILENO);
	r = posix_spawn(&pid, apk_ctx_get_uvol(ac), &act, 0, argv, environ);
	posix_spawn_file_actions_destroy(&act);
	if (r != 0) {
		apk_err(out, "%s: uvol exec error: %s", volname, apk_error_str(r));
		return r;
	}
	close(pipefds[0]);
	os = apk_ostream_to_fd(pipefds[1]);
	apk_stream_copy(is, os, sz, 0, 0, 0);
	r = apk_ostream_close(os);
	if (r != 0) {
		if (r >= 0) r = -APKE_UVOL;
		apk_err(out, "%s: uvol write error: %s", volname, apk_error_str(r));
		return r;
	}

	waitpid(pid, &status, 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		apk_err(out, "%s: uvol exited with error %d", volname, WEXITSTATUS(status));
		return -APKE_UVOL;
	}

	return 0;
}

static int apk_extract_volume(struct apk_ctx *ac, const struct apk_file_info *fi, struct apk_istream *is)
{
	char size[64];
	int r;

	snprintf(size, sizeof size, "%ju", fi->size);
	r = uvol_run(ac, "create", fi->uvol_name, size, "ro");
	if (r != 0) return r;

	r = uvol_extract(ac, fi->uvol_name, size, fi->size, is);
	if (r == 0) r = uvol_run(ac, "up", fi->uvol_name, 0, 0);
	if (r != 0) uvol_run(ac, "remove", fi->uvol_name, 0, 0);
	return r;
}

static int extract_v3_meta(struct apk_extract_ctx *ectx, struct adb *db)
{
	return 0;
}

static int extract_file(struct apk_extract_ctx *ectx, const struct apk_file_info *fi, struct apk_istream *is)
{
	struct extract_ctx *ctx = container_of(ectx, struct extract_ctx, ectx);
	int r;

	if (fi->uvol_name) return apk_extract_volume(ectx->ac, fi, is);

	r = apk_extract_file(ctx->root_fd, fi, 0, 0, is, 0, 0, 0,
		ctx->extract_flags, &ectx->ac->out);
	r = apk_istream_close_error(is, r);

	if (r != 0) unlinkat(ctx->root_fd, fi->name, 0);
	return r;
}

static const struct apk_extract_ops extract_ops = {
	.v2meta = apk_extract_v2_meta,
	.v3meta = extract_v3_meta,
	.file = extract_file,
};

static int extract_main(void *pctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	struct extract_ctx *ctx = pctx;
	struct apk_out *out = &ac->out;
	char **parg;
	int r = 0;

	ctx->ac = ac;
	if (!(ac->force & APK_FORCE_OVERWRITE)) ctx->extract_flags |= APK_EXTRACTF_NO_OVERWRITE;
	if (!ctx->destination) ctx->destination = ".";
	ctx->root_fd = openat(AT_FDCWD, ctx->destination, O_RDONLY);
	if (ctx->root_fd < 0) {
		r = -errno;
		apk_err(out, "Error opening destination '%s': %s",
			ctx->destination, apk_error_str(r));
		return r;
	}

	apk_extract_init(&ctx->ectx, ac, &extract_ops);
	foreach_array_item(parg, args) {
		apk_out(out, "Extracting %s...", *parg);
		r = apk_extract(&ctx->ectx, apk_istream_from_fd_url(AT_FDCWD, *parg, apk_ctx_since(ac, 0)));
		if (r != 0) {
			apk_err(out, "%s: %s", *parg, apk_error_str(r));
			break;
		}
	}
	close(ctx->root_fd);
	return r;
}

static struct apk_applet app_extract = {
	.name = "extract",
	.context_size = sizeof(struct extract_ctx),
	.optgroups = { &optgroup_global, &optgroup_applet },
	.main = extract_main,
};

APK_DEFINE_APPLET(app_extract);

