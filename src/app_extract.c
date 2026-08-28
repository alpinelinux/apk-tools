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
#include <unistd.h>
#include <sys/stat.h>

#include "apk_hash.h"
#include "apk_applet.h"
#include "apk_print.h"
#include "apk_extract.h"
#include "apk_fs.h"

struct extract_dirent {
	apk_hash_node hash_node;
	const char *package;
	mode_t mode;
	unsigned short namelen;
	char name[];
};

static apk_blob_t extract_dirent_get_key(apk_hash_item item)
{
	struct extract_dirent *dirent = item;
	return APK_BLOB_PTR_LEN(dirent->name, dirent->namelen);
}

static const struct apk_hash_ops extract_dirent_hash_ops = {
	.node_offset = offsetof(struct apk_name, hash_node),
	.get_key = extract_dirent_get_key,
	.hash_key = apk_blob_hash,
	.compare = apk_blob_compare,
};

struct extract_ctx {
	const char *destination;
	unsigned int extract_flags;

	struct apk_hash dirents;
	struct apk_extract_ctx ectx;
	struct apk_ctx *ac;
	const char *package;
	int warnings;
};

#define EXTRACT_OPTIONS(OPT) \
	OPT(OPT_EXTRACT_destination,	APK_OPT_ARG "destination") \
	OPT(OPT_EXTRACT_no_chown,	"no-chown")

APK_OPTIONS(extract_options_desc, EXTRACT_OPTIONS);

static int extract_parse_option(void *pctx, struct apk_ctx *ac, int opt, const char *optarg)
{
	struct extract_ctx *ctx = (struct extract_ctx *) pctx;

	switch (opt) {
	case APK_OPTIONS_INIT:
		apk_hash_init(&ctx->dirents, &extract_dirent_hash_ops, 2000);
		break;
	case OPT_EXTRACT_destination:
		ctx->destination = optarg;
		break;
	case OPT_EXTRACT_no_chown:
		ctx->extract_flags |= APK_FSEXTRACTF_NO_CHOWN;
		break;
	default:
		return -ENOTSUP;
	}
	return 0;
}

static int extract_v3_meta(struct apk_extract_ctx *ectx, struct adb_obj *pkg)
{
	return 0;
}

static int extract_file(struct apk_extract_ctx *ectx, const struct apk_file_info *fi, struct apk_istream *is)
{
	struct extract_ctx *ctx = container_of(ectx, struct extract_ctx, ectx);
	struct apk_out *out = &ctx->ac->out;
	char buf[APK_EXTRACTW_BUFSZ];
	apk_blob_t name = APK_BLOB_STR(fi->name), parent;
	int r;

	apk_dbg(out, "%s", fi->name);

	if (apk_blob_ends_with(name, APK_BLOB_STRLIT("/"))) name.len--;

	unsigned long hash = apk_hash_from_key(&ctx->dirents, name);
	struct extract_dirent *de = apk_hash_get_hashed(&ctx->dirents, name, hash);
	if (de) {
		if (S_ISDIR(de->mode) && S_ISDIR(fi->mode)) return 0;
		apk_warn(out, "not extracted '%s': already extracted as different file",
			fi->name);
		goto warn;
	}

	if (apk_blob_rsplit(name, '/', &parent, NULL)) {
		struct extract_dirent *pde = apk_hash_get(&ctx->dirents, parent);
		if (!pde || !S_ISDIR(pde->mode)) {
			apk_warn(out, "not extracted '%s': parent is not a directory",
				fi->name);
			goto warn;
		}
	}

	if (S_ISREG(fi->mode) && fi->link_target) {
		struct extract_dirent *hde = apk_hash_get(&ctx->dirents, APK_BLOB_STR(fi->link_target));
		if (!hde || !S_ISREG(hde->mode) || hde->package != ctx->package) {
			apk_warn(out, "not extracted '%s': hardlink target is not an extracted regular file",
				fi->name);
			goto warn;
		}
	}

	r = apk_fs_extract(ctx->ac, fi, is, ctx->extract_flags, APK_BLOB_NULL);
	if (r == -EEXIST && S_ISDIR(fi->mode)) {
		struct stat st;
		if (fstatat(apk_ctx_fd_dest(ctx->ac), fi->name, &st, AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(st.st_mode))
			r = 0;
	} else if (r > 0) {
		apk_warn(out, "failed to preserve %s: %s",
			fi->name, apk_extract_warning_str(r, buf, sizeof buf));
		r = 0;
	}
	if (r) return r;

	de = apk_balloc_new_extra(&ctx->ac->ba, struct extract_dirent, name.len);
	if (!de) return -ENOMEM;
	*de = (struct extract_dirent) {
		.package = ctx->package,
		.mode = fi->mode,
		.namelen = name.len,
	};
	memcpy(de->name, name.ptr, name.len);
	apk_hash_insert_hashed(&ctx->dirents, de, hash);
	return 0;
warn:
	ctx->warnings++;
	return 0;
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
	int r = 0;

	ctx->ac = ac;
	if (getuid() != 0) ctx->extract_flags |= APK_FSEXTRACTF_NO_CHOWN|APK_FSEXTRACTF_NO_SYS_XATTRS;
	if (!(ac->force & APK_FORCE_OVERWRITE)) ctx->extract_flags |= APK_FSEXTRACTF_NO_OVERWRITE;
	if (!ctx->destination) ctx->destination = ".";

	ac->dest_fd = openat(AT_FDCWD, ctx->destination, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (ac->dest_fd < 0) {
		r = -errno;
		apk_err(out, "Error opening destination '%s': %s",
			ctx->destination, apk_error_str(r));
		return r;
	}

	apk_extract_init(&ctx->ectx, ac, &extract_ops);
	apk_array_foreach_item(arg, args) {
		ctx->package = arg;
		apk_out(out, "Extracting %s...", arg);
		r = apk_extract(&ctx->ectx, apk_istream_from_fd_url(AT_FDCWD, arg, apk_ctx_since(ac, 0)));
		if (r != 0) {
			apk_err(out, "%s: %s", arg, apk_error_str(r));
			break;
		}
	}
	close(ac->dest_fd);
	if (!r && ctx->warnings) r = 1;
	return r;
}

static struct apk_applet app_extract = {
	.name = "extract",
	.options_desc = extract_options_desc,
	.context_size = sizeof(struct extract_ctx),
	.parse = extract_parse_option,
	.main = extract_main,
};

APK_DEFINE_APPLET(app_extract);
