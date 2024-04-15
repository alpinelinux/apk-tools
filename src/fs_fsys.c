/* fsops_sys.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <unistd.h>
#include <sys/stat.h>

#include "apk_fs.h"
#include "apk_xattr.h"
#include "apk_database.h" // for db->atoms

#define TMPNAME_MAX (PATH_MAX + 64)

static int do_fchmodat(int dirfd, const char *pathname, mode_t mode, int flags, struct apk_out *out)
{
	if (fchmodat(dirfd, pathname, mode & 07777, flags) == 0) return 0;
	apk_err(out, "Failed to set permissions on %s: %s", pathname, strerror(errno));
	return -errno;
}

static int do_fchownat(int dirfd, const char *pathname, uid_t uid, gid_t gid, int flags, struct apk_out *out)
{
	if (fchownat(dirfd, pathname, uid, gid, flags) == 0) return 0;
	apk_err(out, "Failed to set ownership on %s: %s", pathname, strerror(errno));
	return -errno;
}

static int fsys_dir_create(struct apk_fsdir *d, mode_t mode, uid_t uid, gid_t gid)
{
	const char *dirname = apk_pathbuilder_cstr(&d->pb);
	if (mkdirat(apk_ctx_fd_dest(d->ac), dirname, mode) < 0) {
		if (errno != EEXIST) apk_err(&d->ac->out, "Failed to create %s: %s", dirname, strerror(errno));
		return -errno;
	}
	if (d->extract_flags & APK_FSEXTRACTF_NO_CHOWN) return 0;
	if (do_fchownat(apk_ctx_fd_dest(d->ac), dirname, uid, gid, 0, &d->ac->out) < 0) return -errno;
	return 0;
}

static int fsys_dir_delete(struct apk_fsdir *d)
{
	if (unlinkat(apk_ctx_fd_dest(d->ac), apk_pathbuilder_cstr(&d->pb), AT_REMOVEDIR) < 0)
		return -errno;
	return 0;
}

static int fsys_dir_check(struct apk_fsdir *d, mode_t mode, uid_t uid, gid_t gid)
{
	struct stat st;

	if (fstatat(apk_ctx_fd_dest(d->ac), apk_pathbuilder_cstr(&d->pb), &st, AT_SYMLINK_NOFOLLOW) != 0)
		return -errno;

	if ((st.st_mode & 07777) != (mode & 07777) || st.st_uid != uid || st.st_gid != gid)
		return APK_FS_DIR_MODIFIED;

	return 0;
}

static int fsys_dir_update_perms(struct apk_fsdir *d, mode_t mode, uid_t uid, gid_t gid)
{
	int fd = apk_ctx_fd_dest(d->ac), rc = 0, r;
	const char *dirname = apk_pathbuilder_cstr(&d->pb);

	r = do_fchmodat(fd, dirname, mode, 0, &d->ac->out);
	if (r) rc = r;
	if (d->extract_flags & APK_FSEXTRACTF_NO_CHOWN) return rc;
	r = do_fchownat(fd, dirname, uid, gid, 0, &d->ac->out);
	if (r) rc = r;
	return rc;
}

static const char *format_tmpname(struct apk_digest_ctx *dctx, apk_blob_t pkgctx,
	apk_blob_t dirname, apk_blob_t fullname, char tmpname[static TMPNAME_MAX])
{
	struct apk_digest d;
	apk_blob_t b = APK_BLOB_PTR_LEN(tmpname, TMPNAME_MAX);

	apk_digest_ctx_reset_alg(dctx, APK_DIGEST_SHA256);
	apk_digest_ctx_update(dctx, pkgctx.ptr, pkgctx.len);
	apk_digest_ctx_update(dctx, fullname.ptr, fullname.len);
	apk_digest_ctx_final(dctx, &d);

	apk_blob_push_blob(&b, dirname);
	if (dirname.len > 0) {
		apk_blob_push_blob(&b, APK_BLOB_STR("/.apk."));
	} else {
		apk_blob_push_blob(&b, APK_BLOB_STR(".apk."));
	}
	apk_blob_push_hexdump(&b, APK_BLOB_PTR_LEN((char *)d.data, 24));
	apk_blob_push_blob(&b, APK_BLOB_PTR_LEN("", 1));

	return tmpname;
}

static apk_blob_t get_dirname(const char *fullname)
{
	char *slash = strrchr(fullname, '/');
	if (!slash) return APK_BLOB_NULL;
	return APK_BLOB_PTR_PTR((char*)fullname, slash);
}

static int is_system_xattr(const char *name)
{
	return strncmp(name, "user.", 5) != 0;
}

static int fsys_file_extract(struct apk_ctx *ac, const struct apk_file_info *fi, struct apk_istream *is,
	apk_progress_cb cb, void *cb_ctx, unsigned int extract_flags, apk_blob_t pkgctx)
{
	char tmpname_file[TMPNAME_MAX], tmpname_linktarget[TMPNAME_MAX];
	struct apk_out *out = &ac->out;
	struct apk_xattr *xattr;
	int fd, r = -1, atflags = 0, ret = 0;
	int atfd = apk_ctx_fd_dest(ac);
	const char *fn = fi->name, *link_target = fi->link_target;

	if (pkgctx.ptr)
		fn = format_tmpname(&ac->dctx, pkgctx, get_dirname(fn),
			APK_BLOB_STR(fn), tmpname_file);

	if (!S_ISDIR(fi->mode) && !(extract_flags & APK_FSEXTRACTF_NO_OVERWRITE)) {
		if (unlinkat(atfd, fn, 0) != 0 && errno != ENOENT) return -errno;
	}

	switch (fi->mode & S_IFMT) {
	case S_IFDIR:
		r = mkdirat(atfd, fn, fi->mode & 07777);
		if (r < 0 && errno != EEXIST)
			ret = -errno;
		break;
	case S_IFREG:
		if (!link_target) {
			int flags = O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC | O_EXCL;
			int fd = openat(atfd, fn, flags, fi->mode & 07777);
			if (fd < 0) {
				ret = -errno;
				break;
			}
			struct apk_ostream *os = apk_ostream_to_fd(fd);
			if (IS_ERR(os)) {
				ret = PTR_ERR(os);
				break;
			}
			apk_stream_copy(is, os, fi->size, cb, cb_ctx, 0);
			r = apk_ostream_close(os);
			if (r < 0) {
				unlinkat(atfd, fn, 0);
				ret = r;
			}
		} else {
			// Hardlink needs to be done against the temporary name
			if (pkgctx.ptr)
				link_target = format_tmpname(&ac->dctx, pkgctx, get_dirname(link_target),
					APK_BLOB_STR(link_target), tmpname_linktarget);
			r = linkat(atfd, link_target, atfd, fn, 0);
			if (r < 0) ret = -errno;
		}
		break;
	case S_IFLNK:
		r = symlinkat(link_target, atfd, fn);
		if (r < 0) ret = -errno;
		atflags |= AT_SYMLINK_NOFOLLOW;
		break;
	case S_IFBLK:
	case S_IFCHR:
	case S_IFIFO:
		r = mknodat(atfd, fn, fi->mode, fi->device);
		if (r < 0) ret = -errno;
		break;
	}
	if (ret) {
		apk_err(out, "Failed to create %s: %s", fi->name, strerror(-ret));
		return ret;
	}

	if (!(extract_flags & APK_FSEXTRACTF_NO_CHOWN)) {
		r = do_fchownat(atfd, fn, fi->uid, fi->gid, atflags, out);
		if (!ret && r) ret = r;

		/* chown resets suid bit so we need set it again */
		if (fi->mode & 07000) {
			r = do_fchmodat(atfd, fn, fi->mode, atflags, out);
			if (!ret && r) ret = r;
		}
	}

	/* extract xattrs */
	if (!S_ISLNK(fi->mode) && fi->xattrs && fi->xattrs->num) {
		r = 0;
		fd = openat(atfd, fn, O_RDWR);
		if (fd >= 0) {
			foreach_array_item(xattr, fi->xattrs) {
				if ((extract_flags & APK_FSEXTRACTF_NO_SYS_XATTRS) && is_system_xattr(xattr->name))
					continue;
				if (apk_fsetxattr(fd, xattr->name, xattr->value.ptr, xattr->value.len) < 0) {
					r = -errno;
					if (r != -ENOTSUP) break;
				}
			}
			close(fd);
		} else {
			r = -errno;
		}
		if (r) {
			if (r != -ENOTSUP)
				apk_err(out, "Failed to set xattrs on %s: %s",
					fn, strerror(-r));
			if (!ret) ret = r;
		}
	}

	if (!S_ISLNK(fi->mode)) {
		/* preserve modification time */
		struct timespec times[2];

		times[0].tv_sec  = times[1].tv_sec  = fi->mtime;
		times[0].tv_nsec = times[1].tv_nsec = 0;
		r = utimensat(atfd, fn, times, atflags);
		if (r < 0) {
			apk_err(out, "Failed to preserve modification time on %s: %s",
				fn, strerror(errno));
			if (!ret || ret == -ENOTSUP) ret = -errno;
		}
	}

	return ret;
}

static int fsys_file_control(struct apk_fsdir *d, apk_blob_t filename, int ctrl)
{
	struct apk_ctx *ac = d->ac;
	char tmpname[TMPNAME_MAX], apknewname[TMPNAME_MAX];
	const char *fn;
	int n, rc = 0, atfd = apk_ctx_fd_dest(d->ac);
	apk_blob_t dirname = apk_pathbuilder_get(&d->pb);

	n = apk_pathbuilder_pushb(&d->pb, filename);
	fn = apk_pathbuilder_cstr(&d->pb);

	switch (ctrl) {
	case APK_FS_CTRL_COMMIT:
		// rename tmpname -> realname
		if (renameat(atfd, format_tmpname(&ac->dctx, d->pkgctx, dirname, apk_pathbuilder_get(&d->pb), tmpname),
			     atfd, fn) < 0)
			rc = -errno;
		break;
	case APK_FS_CTRL_APKNEW:
		// rename tmpname -> realname.apk-new
		snprintf(apknewname, sizeof apknewname, "%s%s", fn, ".apk-new");
		if (renameat(atfd, format_tmpname(&ac->dctx, d->pkgctx, dirname, apk_pathbuilder_get(&d->pb), tmpname),
			     atfd, apknewname) < 0)
			rc = -errno;
		break;
	case APK_FS_CTRL_CANCEL:
		// unlink tmpname
		if (unlinkat(atfd, format_tmpname(&ac->dctx, d->pkgctx, dirname, apk_pathbuilder_get(&d->pb), tmpname), 0) < 0)
			rc = -errno;
		break;
	case APK_FS_CTRL_DELETE:
		// unlink realname
		if (unlinkat(atfd, fn, 0) < 0)
			rc = -errno;
		break;
	default:
		rc = -ENOSYS;
		break;
	}

	apk_pathbuilder_pop(&d->pb, n);
	return rc;
}

static int fsys_file_info(struct apk_fsdir *d, apk_blob_t filename,
			  unsigned int flags, struct apk_file_info *fi)
{
	struct apk_ctx *ac = d->ac;
	int n, r;

	n = apk_pathbuilder_pushb(&d->pb, filename);
	r = apk_fileinfo_get(apk_ctx_fd_dest(ac), apk_pathbuilder_cstr(&d->pb), flags, fi, &ac->db->atoms);
	apk_pathbuilder_pop(&d->pb, n);
	return r;
}

static const struct apk_fsdir_ops fsdir_ops_fsys = {
	.priority = APK_FS_PRIO_DISK,
	.dir_create = fsys_dir_create,
	.dir_delete = fsys_dir_delete,
	.dir_check = fsys_dir_check,
	.dir_update_perms = fsys_dir_update_perms,
	.file_extract = fsys_file_extract,
	.file_control = fsys_file_control,
	.file_info = fsys_file_info,
};

static const struct apk_fsdir_ops *apk_fsops_get(apk_blob_t dir)
{
	if (dir.len >= 4 && memcmp(dir.ptr, "uvol", 4) == 0 && (dir.len == 4 || dir.ptr[4] == '/')) {
		extern const struct apk_fsdir_ops fsdir_ops_uvol;
		return &fsdir_ops_uvol;
	}

	return &fsdir_ops_fsys;
}

int apk_fs_extract(struct apk_ctx *ac, const struct apk_file_info *fi, struct apk_istream *is,
	apk_progress_cb cb, void *cb_ctx, unsigned int extract_flags, apk_blob_t pkgctx)
{
	if (S_ISDIR(fi->mode)) {
		struct apk_fsdir fsd;
		apk_fsdir_get(&fsd, APK_BLOB_STR((char*)fi->name), extract_flags, ac, pkgctx);
		return apk_fsdir_create(&fsd, fi->mode, fi->uid, fi->gid);
	} else {
		const struct apk_fsdir_ops *ops = apk_fsops_get(APK_BLOB_PTR_LEN((char*)fi->name, strnlen(fi->name, 5)));
		return ops->file_extract(ac, fi, is, cb, cb_ctx, extract_flags, pkgctx);
	}
}

void apk_fsdir_get(struct apk_fsdir *d, apk_blob_t dir, unsigned int extract_flags, struct apk_ctx *ac, apk_blob_t pkgctx)
{
	d->ac = ac;
	d->pkgctx = pkgctx;
	d->extract_flags = extract_flags;
	d->ops = apk_fsops_get(dir);
	apk_pathbuilder_setb(&d->pb, dir);
}
