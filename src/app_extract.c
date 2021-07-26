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
#include "apk_adb.h"
#include "apk_pathbuilder.h"

struct extract_ctx {
	const char *destination;
	unsigned int extract_flags;

	struct apk_ctx *ac;
	struct adb db;
	int root_fd;

	struct adb_obj pkg, paths, path, files, file;
	unsigned int cur_path, cur_file;

	struct apk_pathbuilder pb;
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

static void apk_extract_acl(struct apk_file_info *fi, struct adb_obj *o, struct apk_id_cache *idc)
{
	fi->mode = adb_ro_int(o, ADBI_ACL_MODE);
	fi->uid = apk_id_cache_resolve_uid(idc, adb_ro_blob(o, ADBI_ACL_USER), 65534);
	fi->gid = apk_id_cache_resolve_gid(idc, adb_ro_blob(o, ADBI_ACL_GROUP), 65534);
}

static const char *uvol_detect(struct apk_ctx *ac, const char *path)
{
	if (!apk_ctx_get_uvol(ac)) return 0;
	if (strncmp(path, "uvol", 4) != 0) return 0;
	if (path[4] == 0) return path;
	if (path[4] == '/') return &path[5];
	return 0;
}

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

static int uvol_extract(struct apk_ctx *ac, const char *volname, char *arg1, off_t sz, struct apk_istream *is, struct apk_digest_ctx *dctx)
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
	apk_stream_copy(is, os, sz, 0, 0, dctx);
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

static int apk_extract_volume(struct apk_ctx *ac, struct apk_file_info *fi, struct apk_istream *is, struct apk_digest_ctx *dctx)
{
	char size[64];
	int r;

	snprintf(size, sizeof size, "%ju", fi->size);
	r = uvol_run(ac, "create", fi->uvol_name, size, "ro");
	if (r != 0) return r;
	return  uvol_extract(ac, fi->uvol_name, size, fi->size, is, dctx);
}

static int apk_extract_file(struct extract_ctx *ctx, off_t sz, struct apk_istream *is)
{
	struct apk_ctx *ac = ctx->ac;
	struct apk_out *out = &ac->out;
	const char *path_name = apk_pathbuilder_cstr(&ctx->pb);
	struct apk_file_info fi = {
		.name = path_name,
		.uvol_name = uvol_detect(ac, path_name),
		.size = adb_ro_int(&ctx->file, ADBI_FI_SIZE),
		.mtime = adb_ro_int(&ctx->file, ADBI_FI_MTIME),
	};
	struct adb_obj acl;
	struct apk_digest_ctx dctx;
	struct apk_digest d;
	apk_blob_t target;
	int r;

	apk_extract_acl(&fi, adb_ro_obj(&ctx->file, ADBI_FI_ACL, &acl), apk_ctx_get_id_cache(ctx->ac));

	target = adb_ro_blob(&ctx->file, ADBI_FI_TARGET);
	if (!APK_BLOB_IS_NULL(target)) {
		char *target_path;
		uint16_t mode;

		if (target.len < 2) return -APKE_ADB_SCHEMA;
		mode = *(uint16_t*)target.ptr;
		target.ptr += 2;
		target.len -= 2;
		switch (mode) {
		case S_IFBLK:
		case S_IFCHR:
		case S_IFIFO:
			if (target.len != sizeof(uint64_t)) return -APKE_ADB_SCHEMA;
			struct unaligned64 {
				uint64_t value;
			} __attribute__((packed));
			fi.device = ((struct unaligned64 *)target.ptr)->value;
			break;
		case S_IFLNK:
			target_path = alloca(target.len + 1);
			memcpy(target_path, target.ptr, target.len);
			target_path[target.len] = 0;
			fi.link_target = target_path;
			break;
		default:
			return -APKE_ADB_SCHEMA;
		}
		fi.mode |= mode;
		return apk_archive_entry_extract(
			ctx->root_fd, &fi, 0, 0, is, 0, 0, 0,
			ctx->extract_flags, out);
	}

	apk_digest_from_blob(&fi.digest, adb_ro_blob(&ctx->file, ADBI_FI_HASHES));
	if (fi.digest.alg == APK_DIGEST_NONE) return -APKE_ADB_SCHEMA;

	fi.mode |= S_IFREG;
	apk_digest_ctx_init(&dctx, fi.digest.alg);
	if (fi.uvol_name) {
		r = apk_extract_volume(ac, &fi, is, &dctx);
	} else {
		r = apk_archive_entry_extract(
			ctx->root_fd, &fi, 0, 0, is, 0, 0, &dctx,
			ctx->extract_flags, out);
		if (r < 0) return r;
	}
	apk_digest_ctx_final(&dctx, &d);
	apk_digest_ctx_free(&dctx);
	if (r == 0 && apk_digest_cmp(&fi.digest, &d) != 0)
		r = -APKE_FILE_INTEGRITY;
	if (fi.uvol_name) {
		if (r == 0)
			r = uvol_run(ac, "up", fi.uvol_name, 0, 0);
		else
			uvol_run(ac, "remove", fi.uvol_name, 0, 0);
	} else if (r != 0)
		unlinkat(ctx->root_fd, fi.name, 0);
	return r;
}

static int apk_extract_directory(struct extract_ctx *ctx)
{
	struct apk_ctx *ac = ctx->ac;
	struct apk_out *out = &ac->out;
	struct apk_file_info fi = {
		.name = apk_pathbuilder_cstr(&ctx->pb),
	};
	struct adb_obj acl;

	if (uvol_detect(ac, fi.name)) return 0;

	apk_extract_acl(&fi, adb_ro_obj(&ctx->path, ADBI_DI_ACL, &acl), apk_ctx_get_id_cache(ctx->ac));
	fi.mode |= S_IFDIR;

	return apk_archive_entry_extract(
		ctx->root_fd, &fi, 0, 0, 0, 0, 0, 0,
		ctx->extract_flags, out);
}

static int apk_extract_next_file(struct extract_ctx *ctx)
{
	apk_blob_t target;
	int r;

	if (!ctx->cur_path) {
		// one time init
		ctx->cur_path = ADBI_FIRST;
		ctx->cur_file = 0;
		adb_r_rootobj(&ctx->db, &ctx->pkg, &schema_package);
		adb_ro_obj(&ctx->pkg, ADBI_PKG_PATHS, &ctx->paths);
		adb_ro_obj(&ctx->paths, ctx->cur_path, &ctx->path);
		adb_ro_obj(&ctx->path, ADBI_DI_FILES, &ctx->files);
	}

	do {
		ctx->cur_file++;
		while (ctx->cur_file > adb_ra_num(&ctx->files)) {
			ctx->cur_path++;
			ctx->cur_file = ADBI_FIRST;
			if (ctx->cur_path > adb_ra_num(&ctx->paths)) return 1;
			adb_ro_obj(&ctx->paths, ctx->cur_path, &ctx->path);
			apk_pathbuilder_setb(&ctx->pb, adb_ro_blob(&ctx->path, ADBI_DI_NAME));
			adb_ro_obj(&ctx->path, ADBI_DI_FILES, &ctx->files);
			r = apk_extract_directory(ctx);
			if (r != 0) return r;
		}
		adb_ro_obj(&ctx->files, ctx->cur_file, &ctx->file);
		apk_pathbuilder_setb(&ctx->pb, adb_ro_blob(&ctx->path, ADBI_DI_NAME));
		apk_pathbuilder_pushb(&ctx->pb, adb_ro_blob(&ctx->file, ADBI_FI_NAME));
		target = adb_ro_blob(&ctx->file, ADBI_FI_TARGET);
		if (adb_ro_int(&ctx->file, ADBI_FI_SIZE) != 0 &&
		    APK_BLOB_IS_NULL(target)) {
			return 0;
		}
		r = apk_extract_file(ctx, 0, 0);
		if (r != 0) return r;
	} while (1);
}

static int apk_extract_data_block(struct adb *db, struct adb_block *b, struct apk_istream *is)
{
	struct extract_ctx *ctx = container_of(db, struct extract_ctx, db);
	struct adb_data_package *hdr;
	size_t sz = adb_block_length(b);
	int r;

	if (adb_block_type(b) != ADB_BLOCK_DATA) return 0;

	r = apk_extract_next_file(ctx);
	if (r != 0) {
		if (r > 0) r = -APKE_ADB_BLOCK;
		return r;
	}

	hdr = apk_istream_get(is, sizeof *hdr);
	sz -= sizeof *hdr;
	if (IS_ERR(hdr)) return PTR_ERR(hdr);

	if (hdr->path_idx != ctx->cur_path ||
	    hdr->file_idx != ctx->cur_file ||
	    sz != adb_ro_int(&ctx->file, ADBI_FI_SIZE)) {
		// got data for some unexpected file
		return -APKE_ADB_BLOCK;
	}

	return apk_extract_file(ctx, sz, is);
}

static int apk_extract_pkg(struct extract_ctx *ctx, const char *fn)
{
	struct apk_ctx *ac = ctx->ac;
	struct apk_trust *trust = apk_ctx_get_trust(ac);
	int r;

	r = adb_m_process(&ctx->db,
		adb_decompress(apk_istream_from_fd_url(AT_FDCWD, fn, apk_ctx_since(ac, 0)), 0),
		ADB_SCHEMA_PACKAGE, trust, apk_extract_data_block);
	if (r == 0) {
		r = apk_extract_next_file(ctx);
		if (r == 0) r = -APKE_ADB_BLOCK;
		if (r == 1) r = 0;
	}
	adb_free(&ctx->db);
	return r;
}

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

	foreach_array_item(parg, args) {
		apk_out(out, "Extracting %s...", *parg);
		r = apk_extract_pkg(ctx, *parg);
		if (r != 0) {
			apk_err(out, "%s: %s", *parg, apk_error_str(r));
			break;
		}
	}
	close(ctx->root_fd);
	return r;
}

static struct apk_applet apk_extract = {
	.name = "extract",
	.context_size = sizeof(struct extract_ctx),
	.optgroups = { &optgroup_global, &optgroup_applet },
	.main = extract_main,
};

APK_DEFINE_APPLET(apk_extract);

