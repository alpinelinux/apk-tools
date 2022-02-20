/* io_archive.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <utime.h>
#include <string.h>
#include <unistd.h>
#include <sysexits.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <sys/sysmacros.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

#include "apk_defines.h"
#include "apk_print.h"
#include "apk_archive.h"
#include "apk_openssl.h"

struct tar_header {
	/* ustar header, Posix 1003.1 */
	char name[100];     /*   0-99 */
	char mode[8];       /* 100-107 */
	char uid[8];        /* 108-115 */
	char gid[8];        /* 116-123 */
	char size[12];      /* 124-135 */
	char mtime[12];     /* 136-147 */
	char chksum[8];     /* 148-155 */
	char typeflag;      /* 156-156 */
	char linkname[100]; /* 157-256 */
	char magic[8];      /* 257-264 */
	char uname[32];     /* 265-296 */
	char gname[32];     /* 297-328 */
	char devmajor[8];   /* 329-336 */
	char devminor[8];   /* 337-344 */
	char prefix[155];   /* 345-499 */
	char padding[12];   /* 500-511 */
};

#define TAR_BLOB(s)		APK_BLOB_PTR_LEN(s, strnlen(s, sizeof(s)))
#define GET_OCTAL(s,r)		get_octal(s, sizeof(s), r)
#define PUT_OCTAL(s,v,hz)	put_octal(s, sizeof(s), v, hz)

static unsigned int get_octal(char *s, size_t l, int *r)
{
	apk_blob_t b = APK_BLOB_PTR_LEN(s, l);
	unsigned int val = apk_blob_pull_uint(&b, 8);
	while (b.len >= 1 && (b.ptr[0] == 0 || b.ptr[0] == 0x20)) b.ptr++, b.len--;
	if (b.len != 0) *r = -EAPKFORMAT;
	return val;
}

static void put_octal(char *s, size_t l, size_t value, int has_zero)
{
	char *ptr = &s[l - 1];

	if (has_zero) *(ptr--) = '\0';
	while (value != 0 && ptr >= s) {
		*(ptr--) = '0' + (value % 8);
		value /= 8;
	}
	while (ptr >= s)
		*(ptr--) = '0';
}

static int blob_realloc(apk_blob_t *b, size_t newsize)
{
	char *tmp;
	if (b->len >= newsize) return 0;
	tmp = realloc(b->ptr, newsize);
	if (!tmp) return -ENOMEM;
	b->ptr = tmp;
	b->len = newsize;
	return 0;
}

static void handle_extended_header(struct apk_file_info *fi, apk_blob_t hdr)
{
	apk_blob_t name, value;

	while (1) {
		char *start = hdr.ptr;
		unsigned int len = apk_blob_pull_uint(&hdr, 10);
		apk_blob_pull_char(&hdr, ' ');
		if (!apk_blob_split(hdr, APK_BLOB_STR("="), &name, &hdr)) break;
		if (len < hdr.ptr - start + 1) break;
		len -= hdr.ptr - start + 1;
		if (hdr.len < len) break;
		value = APK_BLOB_PTR_LEN(hdr.ptr, len);
		hdr = APK_BLOB_PTR_LEN(hdr.ptr+len, hdr.len-len);
		apk_blob_pull_char(&hdr, '\n');
		if (APK_BLOB_IS_NULL(hdr)) break;
		value.ptr[value.len] = 0;

		if (apk_blob_compare(name, APK_BLOB_STR("path")) == 0) {
			fi->name = value.ptr;
		} else if (apk_blob_compare(name, APK_BLOB_STR("linkpath")) == 0) {
			fi->link_target = value.ptr;
		} else if (apk_blob_pull_blob_match(&name, APK_BLOB_STR("SCHILY.xattr."))) {
			name.ptr[name.len] = 0;
			*apk_xattr_array_add(&fi->xattrs) = (struct apk_xattr) {
				.name = name.ptr,
				.value = value,
			};
		} else if (apk_blob_pull_blob_match(&name, APK_BLOB_STR("APK-TOOLS.checksum."))) {
			int type = APK_CHECKSUM_NONE;
			if (apk_blob_compare(name, APK_BLOB_STR("SHA1")) == 0)
				type = APK_CHECKSUM_SHA1;
			else if (apk_blob_compare(name, APK_BLOB_STR("MD5")) == 0)
				type = APK_CHECKSUM_MD5;
			if (type > fi->csum.type) {
				fi->csum.type = type;
				apk_blob_pull_hexdump(&value, APK_BLOB_CSUM(fi->csum));
				if (APK_BLOB_IS_NULL(value)) fi->csum.type = APK_CHECKSUM_NONE;
			}
		}
	}
}

int apk_tar_parse(struct apk_istream *is, apk_archive_entry_parser parser,
		  void *ctx, struct apk_id_cache *idc)
{
	struct apk_file_info entry;
	struct apk_segment_istream segment;
	struct tar_header buf;
	int end = 0, r;
	size_t toskip, paxlen = 0;
	apk_blob_t pax = APK_BLOB_NULL, longname = APK_BLOB_NULL;
	char filename[sizeof buf.name + sizeof buf.prefix + 2];

	if (IS_ERR_OR_NULL(is)) return PTR_ERR(is) ?: -EINVAL;

	memset(&entry, 0, sizeof(entry));
	entry.name = buf.name;
	while ((r = apk_istream_read(is, &buf, 512)) == 512) {
		if (buf.name[0] == '\0') {
			if (end) break;
			end++;
			continue;
		}
		if (memcmp(buf.magic, "ustar", 5) != 0) {
			r = -EAPKFORMAT;
			goto err;
		}

		r = 0;
		entry = (struct apk_file_info){
			.size  = GET_OCTAL(buf.size, &r),
			.uid   = apk_resolve_uid(idc, TAR_BLOB(buf.uname), GET_OCTAL(buf.uid, &r)),
			.gid   = apk_resolve_gid(idc, TAR_BLOB(buf.gname), GET_OCTAL(buf.gid, &r)),
			.mode  = GET_OCTAL(buf.mode, &r) & 07777,
			.mtime = GET_OCTAL(buf.mtime, &r),
			.name  = entry.name,
			.uname = buf.uname,
			.gname = buf.gname,
			.device = makedev(GET_OCTAL(buf.devmajor, &r),
					  GET_OCTAL(buf.devminor, &r)),
			.xattrs = entry.xattrs,
		};
		if (r != 0) goto err;

		if (buf.prefix[0] && buf.typeflag != 'x' && buf.typeflag != 'g') {
			snprintf(filename, sizeof filename, "%.*s/%.*s",
				 (int) sizeof buf.prefix, buf.prefix,
				 (int) sizeof buf.name, buf.name);
			entry.name = filename;
		}
		buf.mode[0] = 0; /* to nul terminate 100-byte buf.name */
		buf.magic[0] = 0; /* to nul terminate 100-byte buf.linkname */
		apk_xattr_array_resize(&entry.xattrs, 0);

		if (entry.size >= SSIZE_MAX-512) goto err;

		if (paxlen) {
			handle_extended_header(&entry, APK_BLOB_PTR_LEN(pax.ptr, paxlen));
			apk_fileinfo_hash_xattr(&entry);
		}

		toskip = (entry.size + 511) & -512;
		switch (buf.typeflag) {
		case 'L': /* GNU long name extension */
			if ((r = blob_realloc(&longname, entry.size+1)) != 0 ||
			    (r = apk_istream_read(is, longname.ptr, entry.size)) != entry.size)
				goto err;
			entry.name = longname.ptr;
			entry.name[entry.size] = 0;
			toskip -= entry.size;
			break;
		case 'K': /* GNU long link target extension - ignored */
			break;
		case '0':
		case '7': /* regular file */
			entry.mode |= S_IFREG;
			break;
		case '1': /* hard link */
			entry.mode |= S_IFREG;
			if (!entry.link_target) entry.link_target = buf.linkname;
			break;
		case '2': /* symbolic link */
			entry.mode |= S_IFLNK;
			if (!entry.link_target) entry.link_target = buf.linkname;
			break;
		case '3': /* char device */
			entry.mode |= S_IFCHR;
			break;
		case '4': /* block device */
			entry.mode |= S_IFBLK;
			break;
		case '5': /* directory */
			entry.mode |= S_IFDIR;
			break;
		case '6': /* fifo */
			entry.mode |= S_IFIFO;
			break;
		case 'g': /* global pax header */
			break;
		case 'x': /* file specific pax header */
			paxlen = entry.size;
			if ((r = blob_realloc(&pax, (paxlen + 511) & -512)) != 0 ||
			    (r = apk_istream_read(is, pax.ptr, paxlen)) != paxlen)
				goto err;
			toskip -= entry.size;
			break;
		default:
			break;
		}

		if (strnlen(entry.name, PATH_MAX) >= PATH_MAX-10 ||
		    (entry.link_target && strnlen(entry.link_target, PATH_MAX) >= PATH_MAX-10)) {
			r = -ENAMETOOLONG;
			goto err;
		}

		if (entry.mode & S_IFMT) {
			apk_istream_segment(&segment, is, entry.size, entry.mtime);
			r = parser(ctx, &entry, &segment.is);
			if (r != 0) goto err;
			apk_istream_close(&segment.is);

			entry.name = buf.name;
			toskip -= entry.size;
			paxlen = 0;
		}

		if (toskip && (r = apk_istream_read(is, NULL, toskip)) != toskip)
			goto err;
	}

	/* Read remaining end-of-archive records, to ensure we read all of
	 * the file. The underlying istream is likely doing checksumming. */
	if (r == 512) {
		while ((r = apk_istream_read(is, &buf, 512)) == 512) {
			if (buf.name[0] != 0) break;
		}
	}
	if (r == 0) goto ok;
err:
	/* Check that there was no partial (or non-zero) record */
	if (r >= 0) r = -EBADMSG;
ok:
	free(pax.ptr);
	free(longname.ptr);
	apk_fileinfo_free(&entry);
	apk_istream_close(is);
	return r;
}

int apk_tar_write_entry(struct apk_ostream *os, const struct apk_file_info *ae,
			const char *data)
{
	struct tar_header buf;

	memset(&buf, 0, sizeof(buf));
	if (ae != NULL) {
		const unsigned char *src;
	        int chksum, i;

		if (S_ISREG(ae->mode))
			buf.typeflag = '0';
		else
			return -1;

		if (ae->name != NULL)
			strlcpy(buf.name, ae->name, sizeof buf.name);

		strlcpy(buf.uname, ae->uname ?: "root", sizeof buf.uname);
		strlcpy(buf.gname, ae->gname ?: "root", sizeof buf.gname);

		PUT_OCTAL(buf.size, ae->size, 0);
		PUT_OCTAL(buf.uid, ae->uid, 1);
		PUT_OCTAL(buf.gid, ae->gid, 1);
		PUT_OCTAL(buf.mode, ae->mode & 07777, 1);
		PUT_OCTAL(buf.mtime, ae->mtime ?: apk_get_build_time(), 0);

		/* Checksum */
		strcpy(buf.magic, "ustar  ");
		memset(buf.chksum, ' ', sizeof(buf.chksum));
		src = (const unsigned char *) &buf;
		for (i = chksum = 0; i < sizeof(buf); i++)
			chksum += src[i];
		put_octal(buf.chksum, sizeof(buf.chksum)-1, chksum, 1);
	}

	if (apk_ostream_write(os, &buf, sizeof(buf)) != sizeof(buf))
		return -1;

	if (ae == NULL) {
		/* End-of-archive is two empty headers */
		if (apk_ostream_write(os, &buf, sizeof(buf)) != sizeof(buf))
			return -1;
	} else if (data != NULL) {
		if (apk_ostream_write(os, data, ae->size) != ae->size)
			return -1;
		if (apk_tar_write_padding(os, ae) != 0)
			return -1;
	}

	return 0;
}

int apk_tar_write_padding(struct apk_ostream *os, const struct apk_file_info *ae)
{
	static char padding[512];
	int pad;

	pad = 512 - (ae->size & 511);
	if (pad != 512 &&
	    apk_ostream_write(os, padding, pad) != pad)
		return -1;

	return 0;
}

int apk_archive_entry_extract(int atfd, const struct apk_file_info *ae,
			      const char *extract_name, const char *link_target,
			      struct apk_istream *is,
			      apk_progress_cb cb, void *cb_ctx,
			      unsigned int apk_extract_flags)
{
	struct apk_xattr *xattr;
	const char *fn = extract_name ?: ae->name;
	int fd, r = -1, atflags = 0, ret = 0;

	if (unlinkat(atfd, fn, 0) != 0 && errno != ENOENT) return -errno;

	switch (ae->mode & S_IFMT) {
	case S_IFDIR:
		r = mkdirat(atfd, fn, ae->mode & 07777);
		if (r < 0 && errno != EEXIST)
			ret = -errno;
		break;
	case S_IFREG:
		if (ae->link_target == NULL) {
			int flags = O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC | O_EXCL;

			fd = openat(atfd, fn, flags, ae->mode & 07777);
			if (fd < 0) {
				ret = -errno;
				break;
			}
			r = apk_istream_splice(is, fd, ae->size, cb, cb_ctx);
			if (r != ae->size) ret = r < 0 ? r : -ENOSPC;
			close(fd);
		} else {
			r = linkat(atfd, link_target ?: ae->link_target, atfd, fn, 0);
			if (r < 0) ret = -errno;
		}
		break;
	case S_IFLNK:
		r = symlinkat(link_target ?: ae->link_target, atfd, fn);
		if (r < 0) ret = -errno;
		atflags |= AT_SYMLINK_NOFOLLOW;
		break;
	case S_IFBLK:
	case S_IFCHR:
	case S_IFIFO:
		r = mknodat(atfd, fn, ae->mode, ae->device);
		if (r < 0) ret = -errno;
		break;
	}
	if (ret) {
		apk_error("Failed to create %s: %s", ae->name, strerror(-ret));
		return ret;
	}

	if (!(apk_extract_flags & APK_EXTRACTF_NO_CHOWN)) {
		r = fchownat(atfd, fn, ae->uid, ae->gid, atflags);
		if (r < 0) {
			apk_error("Failed to set ownership on %s: %s",
				  fn, strerror(errno));
			if (!ret) ret = -errno;
		}

		/* chown resets suid bit so we need set it again */
		if (ae->mode & 07000) {
			r = fchmodat(atfd, fn, ae->mode & 07777, atflags);
			if (r < 0) {
				apk_error("Failed to set file permissions "
					  "on %s: %s",
					  fn, strerror(errno));
				if (!ret) ret = -errno;
			}
		}
	}

	/* extract xattrs */
	if (!S_ISLNK(ae->mode) && ae->xattrs && ae->xattrs->num) {
		r = 0;
		fd = openat(atfd, fn, O_RDWR);
		if (fd >= 0) {
			foreach_array_item(xattr, ae->xattrs) {
				if (fsetxattr(fd, xattr->name, xattr->value.ptr, xattr->value.len, 0) < 0) {
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
				apk_error("Failed to set xattrs on %s: %s",
					  fn, strerror(-r));
			if (!ret) ret = r;
		}
	}

	if (!S_ISLNK(ae->mode)) {
		/* preserve modification time */
		struct timespec times[2];

		times[0].tv_sec  = times[1].tv_sec  = ae->mtime;
		times[0].tv_nsec = times[1].tv_nsec = 0;
		r = utimensat(atfd, fn, times, atflags);
		if (r < 0) {
			apk_error("Failed to preserve modification time on %s: %s",
				fn, strerror(errno));
			if (!ret || ret == -ENOTSUP) ret = -errno;
		}
	}

	return ret;
}
