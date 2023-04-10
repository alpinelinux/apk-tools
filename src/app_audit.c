/* app_audit.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <fnmatch.h>
#include <limits.h>
#include <sys/stat.h>
#include "apk_applet.h"
#include "apk_database.h"
#include "apk_print.h"

/* Use (unused) highest bit of mode_t as seen flag of our internal
 * database file entries */
#define S_SEENFLAG	0x80000000

enum {
	MODE_BACKUP = 0,
	MODE_SYSTEM,
	MODE_FULL,
};

struct audit_ctx {
	unsigned mode : 2;
	unsigned recursive : 1;
	unsigned check_permissions : 1;
	unsigned packages_only : 1;
	unsigned ignore_busybox_symlinks : 1;
	unsigned details : 1;
};

#define AUDIT_OPTIONS(OPT) \
	OPT(OPT_AUDIT_backup,			"backup") \
	OPT(OPT_AUDIT_check_permissions,	"check-permissions") \
	OPT(OPT_AUDIT_details,			"details") \
	OPT(OPT_AUDIT_full,			"full") \
	OPT(OPT_AUDIT_ignore_busybox_symlinks,	"ignore-busybox-symlinks") \
	OPT(OPT_AUDIT_packages,			"packages") \
	OPT(OPT_AUDIT_protected_paths,		APK_OPT_ARG "protected-paths") \
	OPT(OPT_AUDIT_recursive,		APK_OPT_SH("r") "recursive") \
	OPT(OPT_AUDIT_system,			"system")

APK_OPT_APPLET(option_desc, AUDIT_OPTIONS);

static int option_parse_applet(void *ctx, struct apk_db_options *dbopts, int opt, const char *optarg)
{
	struct audit_ctx *actx = (struct audit_ctx *) ctx;
	int r;

	switch (opt) {
	case OPT_AUDIT_backup:
		actx->mode = MODE_BACKUP;
		break;
	case OPT_AUDIT_full:
		actx->mode = MODE_FULL;
		if (APK_BLOB_IS_NULL(dbopts->protected_paths))
			dbopts->protected_paths = APK_BLOB_STR(
				"+etc\n"
				"@etc/init.d\n"
				"-dev\n"
				"-home\n"
				"-lib/apk\n"
				"-lib/rc/cache\n"
				"-proc\n"
				"-root\n"
				"-run\n"
				"-sys\n"
				"-tmp\n"
				"-var\n"
				);
		break;
	case OPT_AUDIT_system:
		actx->mode = MODE_SYSTEM;
		break;
	case OPT_AUDIT_check_permissions:
		actx->check_permissions = 1;
		break;
	case OPT_AUDIT_details:
		actx->details = 1;
		break;
	case OPT_AUDIT_ignore_busybox_symlinks:
		actx->ignore_busybox_symlinks = 1;
		break;
	case OPT_AUDIT_packages:
		actx->packages_only = 1;
		break;
	case OPT_AUDIT_protected_paths:
		r = apk_blob_from_file(AT_FDCWD, optarg, &dbopts->protected_paths);
		if (r) {
			apk_error("unable to read protected path file: %s: %s", optarg, apk_error_str(r));
			return r;
		}
		break;
	case OPT_AUDIT_recursive:
		actx->recursive = 1;
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

struct audit_tree_ctx {
	struct audit_ctx *actx;
	struct apk_database *db;
	struct apk_db_dir *dir;
	size_t pathlen;
	char path[PATH_MAX];
};

static int audit_file(struct audit_ctx *actx,
		      struct apk_database *db,
		      struct apk_db_file *dbf,
		      int dirfd, const char *name,
		      struct apk_file_info *fi)
{
	int rv = 0;

	if (!dbf) return 'A';

	if (apk_fileinfo_get(dirfd, name,
				APK_FI_NOFOLLOW |
				APK_FI_XATTR_CSUM(dbf->acl->xattr_csum.type ?: APK_CHECKSUM_DEFAULT) |
				APK_FI_CSUM(dbf->csum.type),
				fi, &db->atoms) != 0)
		return 'e';

	if (dbf->csum.type != APK_CHECKSUM_NONE &&
	    apk_checksum_compare(&fi->csum, &dbf->csum) != 0)
		rv = 'U';
	else if (!S_ISLNK(fi->mode) && !dbf->diri->pkg->ipkg->broken_xattr &&
	         apk_checksum_compare(&fi->xattr_csum, &dbf->acl->xattr_csum) != 0)
		rv = 'x';
	else if (S_ISLNK(fi->mode) && dbf->csum.type == APK_CHECKSUM_NONE)
		rv = 'U';
	else if (actx->check_permissions) {
		if ((fi->mode & 07777) != (dbf->acl->mode & 07777))
			rv = 'M';
		else if (fi->uid != dbf->acl->uid || fi->gid != dbf->acl->gid)
			rv = 'M';
	}

	return rv;
}

static int audit_directory(struct audit_ctx *actx,
			   struct apk_database *db,
			   struct apk_db_dir *dbd,
			   struct apk_file_info *fi)
{
	if (dbd != NULL) dbd->mode |= S_SEENFLAG;

	if (dbd == NULL || dbd->refs == 1)
		return actx->recursive ? 'd' : 'D';

	if (actx->check_permissions &&
	    ((dbd->mode & ~S_SEENFLAG) || dbd->uid || dbd->gid)) {
		if ((fi->mode & 07777) != (dbd->mode & 07777))
			return 'm';
		if (fi->uid != dbd->uid || fi->gid != dbd->gid)
			return 'm';
	}

	return 0;
}

static const char *format_checksum(const apk_blob_t csum, apk_blob_t b)
{
	const char *ret = b.ptr;
	if (csum.len == 0) return "";
	apk_blob_push_blob(&b, APK_BLOB_STR(" hash="));
	apk_blob_push_hexdump(&b, csum);
	apk_blob_push_blob(&b, APK_BLOB_PTR_LEN("", 1));
	return ret;
}

static void report_audit(struct audit_ctx *actx,
			 char reason, apk_blob_t bfull,
			 struct apk_db_dir *dir,
			 struct apk_db_file *file,
			 struct apk_file_info *fi)
{
	struct apk_package *pkg = file ? file->diri->pkg : NULL;
	char csum_buf[8+APK_BLOB_CHECKSUM_BUF];

	if (!reason) return;

	if (actx->packages_only) {
		if (!pkg || pkg->state_int != 0) return;
		pkg->state_int = 1;
		if (apk_verbosity < 1)
			printf("%s\n", pkg->name->name);
		else
			printf(PKG_VER_FMT "\n", PKG_VER_PRINTF(pkg));
	} else if (apk_verbosity < 1) {
		printf(BLOB_FMT "\n", BLOB_PRINTF(bfull));
	} else {
		if (actx->details) {
			if (file)
				printf("- mode=%o uid=%d gid=%d%s\n",
					file->acl->mode & 07777, file->acl->uid, file->acl->gid,
					format_checksum(APK_BLOB_CSUM(file->csum), APK_BLOB_BUF(csum_buf)));
			else if (dir && reason != 'D' && reason != 'd')
				printf("- mode=%o uid=%d gid=%d\n",
					dir->mode & 07777, dir->uid, dir->gid);
			if (fi) printf("+ mode=%o uid=%d gid=%d%s\n",
				fi->mode & 07777, fi->uid, fi->gid,
				format_checksum(APK_BLOB_CSUM(fi->csum), APK_BLOB_BUF(csum_buf)));
		}
		printf("%c " BLOB_FMT "\n", reason, BLOB_PRINTF(bfull));
	}
}

static int determine_file_protect_mode(struct apk_db_dir *dir, const char *name)
{
	struct apk_protected_path *ppath;
	int protect_mode = dir->protect_mode;

	/* inherit file's protection mask */
	foreach_array_item(ppath, dir->protected_paths) {
		char *slash = strchr(ppath->relative_pattern, '/');
		if (slash == NULL) {
			if (fnmatch(ppath->relative_pattern, name, FNM_PATHNAME) != 0)
				continue;
			protect_mode = ppath->protect_mode;
		}
	}
	return protect_mode;
}

static int audit_directory_tree_item(void *ctx, int dirfd, const char *name)
{
	struct audit_tree_ctx *atctx = (struct audit_tree_ctx *) ctx;
	apk_blob_t bdir = APK_BLOB_PTR_LEN(atctx->path, atctx->pathlen);
	apk_blob_t bent = APK_BLOB_STR(name);
	apk_blob_t bfull;
	struct audit_ctx *actx = atctx->actx;
	struct apk_database *db = atctx->db;
	struct apk_db_dir *dir = atctx->dir, *child = NULL;
	struct apk_db_file *dbf;
	struct apk_file_info fi;
	int reason = 0;

	if (bdir.len + bent.len + 1 >= sizeof(atctx->path)) return 0;

	memcpy(&atctx->path[atctx->pathlen], bent.ptr, bent.len);
	atctx->pathlen += bent.len;
	bfull = APK_BLOB_PTR_LEN(atctx->path, atctx->pathlen);

	if (apk_fileinfo_get(dirfd, name, APK_FI_NOFOLLOW, &fi, &db->atoms) < 0) {
		dbf = apk_db_file_query(db, bdir, bent);
		if (dbf) dbf->audited = 1;
		report_audit(actx, 'e', bfull, NULL, dbf, NULL);
		goto done;
	}

	if (S_ISDIR(fi.mode)) {
		int recurse = TRUE;

		switch (actx->mode) {
		case MODE_BACKUP:
			child = apk_db_dir_get(db, bfull);
			if (!child->has_protected_children)
				recurse = FALSE;
			if (apk_protect_mode_none(child->protect_mode))
				goto recurse_check;
			break;
		case MODE_SYSTEM:
			child = apk_db_dir_query(db, bfull);
			if (child == NULL) goto done;
			child = apk_db_dir_ref(child);
			break;
		case MODE_FULL:
			child = apk_db_dir_get(db, bfull);
			if (child->protect_mode == APK_PROTECT_NONE) break;
			goto recurse_check;
		}

		reason = audit_directory(actx, db, child, &fi);

recurse_check:
		atctx->path[atctx->pathlen++] = '/';
		bfull.len++;
		report_audit(actx, reason, bfull, dir, NULL, &fi);
		if (reason != 'D' && recurse) {
			atctx->dir = child;
			reason = apk_dir_foreach_file(
				openat(dirfd, name, O_RDONLY|O_CLOEXEC),
				audit_directory_tree_item, atctx);
			atctx->dir = dir;
		}
		bfull.len--;
		atctx->pathlen--;
	} else {
		int protect_mode = determine_file_protect_mode(dir, name);

		dbf = apk_db_file_query(db, bdir, bent);
		if (dbf) dbf->audited = 1;

		switch (actx->mode) {
		case MODE_FULL:
			switch (protect_mode) {
			case APK_PROTECT_NONE:
				break;
			case APK_PROTECT_SYMLINKS_ONLY:
				if (S_ISLNK(fi.mode)) goto done;
				break;
			case APK_PROTECT_IGNORE:
			case APK_PROTECT_ALL:
			case APK_PROTECT_CHANGED:
				goto done;
			}
			break;
		case MODE_BACKUP:
			switch (protect_mode) {
			case APK_PROTECT_NONE:
			case APK_PROTECT_IGNORE:
				goto done;
			case APK_PROTECT_CHANGED:
				break;
			case APK_PROTECT_SYMLINKS_ONLY:
				if (!S_ISLNK(fi.mode)) goto done;
				break;
			case APK_PROTECT_ALL:
				reason = 'A';
				break;
			}
			if ((!dbf || reason == 'A') &&
			    apk_blob_ends_with(bent, APK_BLOB_STR(".apk-new")))
				goto done;
			break;
		case MODE_SYSTEM:
			if (!dbf || !apk_protect_mode_none(protect_mode)) goto done;
			break;
		}

		if (!dbf && actx->ignore_busybox_symlinks && S_ISLNK(fi.mode)) {
			char target[16];
			ssize_t n;
			n = readlinkat(dirfd, name, target, sizeof target);
			if (n == 12 && memcmp(target, "/bin/busybox", 12) == 0)
				goto done;
			if (n == 11 && memcmp(target, "/bin/bbsuid", 11) == 0)
				goto done;
		}
		if (!reason) reason = audit_file(actx, db, dbf, dirfd, name, &fi);
		report_audit(actx, reason, bfull, NULL, dbf, &fi);
		apk_fileinfo_free(&fi);
	}

done:
	if (child)
		apk_db_dir_unref(db, child, FALSE);

	atctx->pathlen -= bent.len;
	return 0;
}

static int audit_directory_tree(struct audit_tree_ctx *atctx, int dirfd)
{
	apk_blob_t path;
	int r;

	path = APK_BLOB_PTR_LEN(atctx->path, atctx->pathlen);
	if (path.len && path.ptr[path.len-1] == '/')
		path.len--;

	atctx->dir = apk_db_dir_get(atctx->db, path);
	atctx->dir->mode |= S_SEENFLAG;
	r = apk_dir_foreach_file(dirfd, audit_directory_tree_item, atctx);
	apk_db_dir_unref(atctx->db, atctx->dir, FALSE);

	return r;
}

static int audit_missing_files(apk_hash_item item, void *pctx)
{
	struct audit_ctx *actx = pctx;
	struct apk_db_file *file = item;
	struct apk_db_dir *dir;
	char path[PATH_MAX];
	int len;

	if (file->audited) return 0;

	dir = file->diri->dir;
	if (!(dir->mode & S_SEENFLAG)) return 0;
	if (determine_file_protect_mode(dir, file->name) == APK_PROTECT_IGNORE) return 0;

	len = snprintf(path, sizeof(path), DIR_FILE_FMT, DIR_FILE_PRINTF(dir, file));
	report_audit(actx, 'X', APK_BLOB_PTR_LEN(path, len), NULL, file, NULL);
	return 0;
}

static int audit_main(void *ctx, struct apk_database *db, struct apk_string_array *args)
{
	struct audit_tree_ctx atctx;
	struct audit_ctx *actx = (struct audit_ctx *) ctx;
	char **parg, *arg;
	int r = 0;

	atctx.db = db;
	atctx.actx = actx;
	atctx.pathlen = 0;
	atctx.path[0] = 0;

	if (args->num == 0) {
		r |= audit_directory_tree(&atctx, dup(db->root_fd));
	} else {
		foreach_array_item(parg, args) {
			arg = *parg;
			if (arg[0] != '/') {
				apk_warning("%s: relative path skipped.\n", arg);
				continue;
			}
			arg++;
			atctx.pathlen = strlen(arg);
			memcpy(atctx.path, arg, atctx.pathlen);
			if (atctx.path[atctx.pathlen-1] != '/')
				atctx.path[atctx.pathlen++] = '/';

			r |= audit_directory_tree(&atctx, openat(db->root_fd, arg, O_RDONLY|O_CLOEXEC));
		}
	}
	if (actx->mode == MODE_SYSTEM || actx->mode == MODE_FULL)
		apk_hash_foreach(&db->installed.files, audit_missing_files, ctx);

	return r;
}

static struct apk_applet apk_audit = {
	.name = "audit",
	.open_flags = APK_OPENF_READ|APK_OPENF_NO_SCRIPTS|APK_OPENF_NO_REPOS,
	.context_size = sizeof(struct audit_ctx),
	.optgroups = { &optgroup_global, &optgroup_applet },
	.main = audit_main,
};

APK_DEFINE_APPLET(apk_audit);

