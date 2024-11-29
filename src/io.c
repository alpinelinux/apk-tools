/* io.c - Alpine Package Keeper (APK)
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
#include <endian.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>

#include "apk_defines.h"
#include "apk_io.h"
#include "apk_hash.h"
#include "apk_openssl.h"

#if defined(__GLIBC__) || defined(__UCLIBC__)
#define HAVE_FGETPWENT_R
#define HAVE_FGETGRENT_R
#endif

size_t apk_io_bufsize = 128*1024;

static inline int atfd_error(int atfd)
{
	return atfd < -1 && atfd != AT_FDCWD;
}

static void apk_file_meta_from_fd(int fd, struct apk_file_meta *meta)
{
	struct stat st;

	if (fstat(fd, &st) == 0) {
		meta->mtime = st.st_mtime;
		meta->atime = st.st_atime;
	} else {
		memset(meta, 0, sizeof(*meta));
	}
}

void apk_file_meta_to_fd(int fd, struct apk_file_meta *meta)
{
	struct timespec times[2] = {
		{ .tv_sec = meta->atime, .tv_nsec = meta->atime ? 0 : UTIME_OMIT },
		{ .tv_sec = meta->mtime, .tv_nsec = meta->mtime ? 0 : UTIME_OMIT }
	};
	futimens(fd, times);
}

ssize_t apk_istream_read(struct apk_istream *is, void *ptr, size_t size)
{
	ssize_t left = size, r = 0;

	while (left) {
		if (is->ptr != is->end) {
			r = min(left, is->end - is->ptr);
			if (ptr) {
				memcpy(ptr, is->ptr, r);
				ptr += r;
			}
			is->ptr += r;
			left -= r;
			continue;
		}
		if (is->err) break;

		if (ptr && left > is->buf_size/4) {
			r = is->ops->read(is, ptr, left);
			if (r <= 0) break;
			left -= r;
			ptr += r;
			continue;
		}

		r = is->ops->read(is, is->buf, is->buf_size);
		if (r <= 0) break;

		is->ptr = is->buf;
		is->end = is->buf + r;
	}

	if (r < 0) return r;
	if (size && left == size && !is->err) is->err = 1;
	if (size == left) return is->err < 0 ? is->err : 0;
	return size - left;
}

static int __apk_istream_fill(struct apk_istream *is)
{
	ssize_t sz;

	if (is->err) return is->err;

	if (is->ptr != is->buf) {
		sz = is->end - is->ptr;
		memmove(is->buf, is->ptr, sz);
		is->ptr = is->buf;
		is->end = is->buf + sz;
	}

	sz = is->ops->read(is, is->end, is->buf + is->buf_size - is->end);
	if (sz <= 0) {
		is->err = sz ?: 1;
		return is->err;
	}
	is->end += sz;
	return 0;
}

apk_blob_t apk_istream_get(struct apk_istream *is, size_t len)
{
	apk_blob_t ret = APK_BLOB_NULL;

	if (is->err < 0) return (struct apk_blob) { .len = is->err };

	do {
		if (is->end - is->ptr >= len) {
			ret = APK_BLOB_PTR_LEN((char*)is->ptr, len);
			break;
		}
		if (is->err>0 || is->end-is->ptr == is->buf_size) {
			ret = APK_BLOB_PTR_LEN((char*)is->ptr, is->end - is->ptr);
			break;
		}
	} while (!__apk_istream_fill(is));

	if (!APK_BLOB_IS_NULL(ret)) {
		is->ptr = (uint8_t*)ret.ptr + ret.len;
		return ret;
	}

	return (struct apk_blob) { .len = is->err < 0 ? is->err : 0 };
}

apk_blob_t apk_istream_get_max(struct apk_istream *is, size_t max)
{
	if (is->err < 0) return (struct apk_blob) { .len = is->err };

	if (is->ptr == is->end) __apk_istream_fill(is);

	if (is->ptr != is->end) {
		apk_blob_t ret = APK_BLOB_PTR_LEN((char*)is->ptr, min((size_t)(is->end - is->ptr), max));
		is->ptr += ret.len;
		return ret;
	}

	return (struct apk_blob) { .len = is->err < 0 ? is->err : 0 };
}

apk_blob_t apk_istream_get_delim(struct apk_istream *is, apk_blob_t token)
{
	apk_blob_t ret = APK_BLOB_NULL, left = APK_BLOB_NULL;

	do {
		if (apk_blob_split(APK_BLOB_PTR_LEN((char*)is->ptr, is->end - is->ptr), token, &ret, &left))
			break;
		if (is->end - is->ptr == is->buf_size) {
			is->err = -ENOBUFS;
			break;
		}
	} while (!__apk_istream_fill(is));

	/* Last segment before end-of-file. Return also zero length non-null
	 * blob if eof comes immediately after the delimiter. */
	if (is->ptr && is->err > 0)
		ret = APK_BLOB_PTR_LEN((char*)is->ptr, is->end - is->ptr);

	if (!APK_BLOB_IS_NULL(ret)) {
		is->ptr = (uint8_t*)left.ptr;
		is->end = (uint8_t*)left.ptr + left.len;
		return ret;
	}
	return (struct apk_blob) { .len = is->err < 0 ? is->err : 0 };
}

static void segment_get_meta(struct apk_istream *is, struct apk_file_meta *meta)
{
	struct apk_segment_istream *sis = container_of(is, struct apk_segment_istream, is);
	*meta = (struct apk_file_meta) {
		.atime = sis->mtime,
		.mtime = sis->mtime,
	};
}

static ssize_t segment_read(struct apk_istream *is, void *ptr, size_t size)
{
	struct apk_segment_istream *sis = container_of(is, struct apk_segment_istream, is);
	ssize_t r;

	if (size > sis->bytes_left) size = sis->bytes_left;
	if (size == 0) return 0;

	r = sis->pis->ops->read(sis->pis, ptr, size);
	if (r <= 0) {
		/* If inner stream returned zero (end-of-stream), we
		 * are getting short read, because tar header indicated
		 * more was to be expected. */
		if (r == 0) r = -ECONNABORTED;
	} else {
		sis->bytes_left -= r;
	}
	return r;
}

static int segment_close(struct apk_istream *is)
{
	int r = is->err;
	struct apk_segment_istream *sis = container_of(is, struct apk_segment_istream, is);

	if (sis->bytes_left) {
		apk_istream_read(sis->pis, NULL, sis->bytes_left);
		sis->bytes_left = 0;
	}
	return r < 0 ? r : 0;
}

static const struct apk_istream_ops segment_istream_ops = {
	.get_meta = segment_get_meta,
	.read = segment_read,
	.close = segment_close,
};

struct apk_istream *apk_istream_segment(struct apk_segment_istream *sis, struct apk_istream *is, size_t len, time_t mtime)
{
	*sis = (struct apk_segment_istream) {
		.is.ops = &segment_istream_ops,
		.is.buf = is->buf,
		.is.buf_size = is->buf_size,
		.is.ptr = is->ptr,
		.is.end = is->end,
		.pis = is,
		.bytes_left = len,
		.mtime = mtime,
	};
	if (sis->is.end - sis->is.ptr > len) {
		sis->is.end = sis->is.ptr + len;
		is->ptr += len;
	} else {
		is->ptr = is->end = 0;
	}
	sis->bytes_left -= sis->is.end - sis->is.ptr;
	return &sis->is;
}

struct apk_tee_istream {
	struct apk_istream is;
	struct apk_istream *inner_is;
	int fd, copy_meta;
	size_t size;
	apk_progress_cb cb;
	void *cb_ctx;
};

static void tee_get_meta(struct apk_istream *is, struct apk_file_meta *meta)
{
	struct apk_tee_istream *tee = container_of(is, struct apk_tee_istream, is);
	apk_istream_get_meta(tee->inner_is, meta);
}

static ssize_t __tee_write(struct apk_tee_istream *tee, void *ptr, size_t size)
{
	ssize_t w = write(tee->fd, ptr, size);
	if (size != w) {
		if (w < 0) return w;
		return -ENOSPC;
	}
	tee->size += size;
	if (tee->cb) tee->cb(tee->cb_ctx, tee->size);
	return size;
}

static ssize_t tee_read(struct apk_istream *is, void *ptr, size_t size)
{
	struct apk_tee_istream *tee = container_of(is, struct apk_tee_istream, is);
	ssize_t r;

	r = tee->inner_is->ops->read(tee->inner_is, ptr, size);
	if (r <= 0) return r;

	return __tee_write(tee, ptr, r);
}

static int tee_close(struct apk_istream *is)
{
	int r;
	struct apk_tee_istream *tee = container_of(is, struct apk_tee_istream, is);
	struct apk_file_meta meta;

	if (tee->copy_meta) {
		apk_istream_get_meta(tee->inner_is, &meta);
		apk_file_meta_to_fd(tee->fd, &meta);
	}

	r = apk_istream_close(tee->inner_is);
	if (tee->fd > STDERR_FILENO) close(tee->fd);
	free(tee);
	return r;
}

static const struct apk_istream_ops tee_istream_ops = {
	.get_meta = tee_get_meta,
	.read = tee_read,
	.close = tee_close,
};

struct apk_istream *apk_istream_tee_fd(struct apk_istream *from, int fd, int flags, apk_progress_cb cb, void *cb_ctx)
{
	struct apk_tee_istream *tee;
	int r;

	if (IS_ERR_OR_NULL(from)) {
		r = PTR_ERR(from);
		goto err;
	}
	if (fd < 0) {
		r = -EBADFD;
		goto err;
	}

	tee = malloc(sizeof *tee);
	if (!tee) {
		r = -ENOMEM;
		goto err;
	}

	*tee = (struct apk_tee_istream) {
		.is.ops = &tee_istream_ops,
		.is.buf = from->buf,
		.is.buf_size = from->buf_size,
		.is.ptr = from->ptr,
		.is.end = from->end,
		.inner_is = from,
		.fd = fd,
		.copy_meta = flags & APK_ISTREAM_TEE_COPY_META,
		.cb = cb,
		.cb_ctx = cb_ctx,
	};

	if (from->ptr != from->end) {
		r = __tee_write(tee, from->ptr, from->end - from->ptr);
		if (r < 0) goto err_free;
	}

	return &tee->is;
err_free:
	free(tee);
err:
	if (fd > STDERR_FILENO) close(fd);
	if (IS_ERR(from)) return ERR_CAST(from);
	if (flags & APK_ISTREAM_TEE_OPTIONAL) return from;
	apk_istream_close(from);
	return ERR_PTR(r);
}

struct apk_istream *apk_istream_tee(struct apk_istream *from, int atfd, const char *to, int flags, apk_progress_cb cb, void *cb_ctx)
{
	int fd, r;

	if (IS_ERR(from)) return ERR_CAST(from);
	if (atfd_error(atfd)) {
		r = atfd;
		goto err;
	}
	fd = openat(atfd, to, O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		r = -errno;
		goto err;
	}
	return apk_istream_tee_fd(from, fd, flags, cb, cb_ctx);
err:
	if (flags & APK_ISTREAM_TEE_OPTIONAL) return from;
	apk_istream_close(from);
	return ERR_PTR(r);
}

struct apk_mmap_istream {
	struct apk_istream is;
	int fd;
};

static void mmap_get_meta(struct apk_istream *is, struct apk_file_meta *meta)
{
	struct apk_mmap_istream *mis = container_of(is, struct apk_mmap_istream, is);
	return apk_file_meta_from_fd(mis->fd, meta);
}

static ssize_t mmap_read(struct apk_istream *is, void *ptr, size_t size)
{
	return 0;
}

static int mmap_close(struct apk_istream *is)
{
	int r = is->err;
	struct apk_mmap_istream *mis = container_of(is, struct apk_mmap_istream, is);

	munmap(mis->is.buf, mis->is.buf_size);
	close(mis->fd);
	free(mis);
	return r < 0 ? r : 0;
}

static const struct apk_istream_ops mmap_istream_ops = {
	.get_meta = mmap_get_meta,
	.read = mmap_read,
	.close = mmap_close,
};

static inline struct apk_istream *apk_mmap_istream_from_fd(int fd)
{
	struct apk_mmap_istream *mis;
	struct stat st;
	void *ptr;

	if (fstat(fd, &st) < 0) return ERR_PTR(-errno);

	ptr = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) return ERR_PTR(-errno);

	mis = malloc(sizeof *mis);
	if (mis == NULL) {
		munmap(ptr, st.st_size);
		return ERR_PTR(-ENOMEM);
	}

	*mis = (struct apk_mmap_istream) {
		.is.flags = APK_ISTREAM_SINGLE_READ,
		.is.err = 1,
		.is.ops = &mmap_istream_ops,
		.is.buf = ptr,
		.is.buf_size = st.st_size,
		.is.ptr = ptr,
		.is.end = ptr + st.st_size,
		.fd = fd,
	};
	return &mis->is;
}

struct apk_fd_istream {
	struct apk_istream is;
	int fd;
};

static void fdi_get_meta(struct apk_istream *is, struct apk_file_meta *meta)
{
	struct apk_fd_istream *fis = container_of(is, struct apk_fd_istream, is);
	apk_file_meta_from_fd(fis->fd, meta);
}

static ssize_t fdi_read(struct apk_istream *is, void *ptr, size_t size)
{
	struct apk_fd_istream *fis = container_of(is, struct apk_fd_istream, is);
	ssize_t r;

	r = read(fis->fd, ptr, size);
	if (r < 0) return -errno;
	return r;
}

static int fdi_close(struct apk_istream *is)
{
	int r = is->err;
	struct apk_fd_istream *fis = container_of(is, struct apk_fd_istream, is);

	close(fis->fd);
	free(fis);
	return r < 0 ? r : 0;
}

static const struct apk_istream_ops fd_istream_ops = {
	.get_meta = fdi_get_meta,
	.read = fdi_read,
	.close = fdi_close,
};

struct apk_istream *apk_istream_from_fd(int fd)
{
	struct apk_fd_istream *fis;

	if (fd < 0) return ERR_PTR(-EBADF);

	fis = malloc(sizeof(*fis) + apk_io_bufsize);
	if (fis == NULL) {
		close(fd);
		return ERR_PTR(-ENOMEM);
	}

	*fis = (struct apk_fd_istream) {
		.is.ops = &fd_istream_ops,
		.is.buf = (uint8_t *)(fis + 1),
		.is.buf_size = apk_io_bufsize,
		.fd = fd,
	};

	return &fis->is;
}

struct apk_istream *apk_istream_from_file(int atfd, const char *file)
{
	int fd;

	if (atfd_error(atfd)) return ERR_PTR(atfd);

	fd = openat(atfd, file, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return ERR_PTR(-errno);

	if (0) {
		struct apk_istream *is = apk_mmap_istream_from_fd(fd);
		if (!IS_ERR_OR_NULL(is)) return is;
	}
	return apk_istream_from_fd(fd);
}

ssize_t apk_stream_copy(struct apk_istream *is, struct apk_ostream *os, size_t size,
			apk_progress_cb cb, void *cb_ctx, EVP_MD_CTX *mdctx)
{
	size_t done = 0;
	apk_blob_t d;
	int r;

	while (done < size) {
		if (cb != NULL) cb(cb_ctx, done);

		d = apk_istream_get_max(is, size - done);
		if (APK_BLOB_IS_NULL(d)) {
			if (d.len) return d.len;
			if (size != APK_IO_ALL) return -EBADMSG;
			break;
		}
		if (mdctx) EVP_DigestUpdate(mdctx, d.ptr, d.len);

		r = apk_ostream_write(os, d.ptr, d.len);
		if (r < 0) return r;

		done += d.len;
	}
	return done;
}

ssize_t apk_istream_splice(struct apk_istream *is, int fd, size_t size,
			   apk_progress_cb cb, void *cb_ctx)
{
	static void *splice_buffer = NULL;
	unsigned char *buf, *mmapbase = MAP_FAILED;
	size_t bufsz, done = 0, togo;
	ssize_t r;

	bufsz = size;
	if (size > 128 * 1024) {
		if (size != APK_IO_ALL) {
			r = posix_fallocate(fd, 0, size);
			if (r == 0)
				mmapbase = mmap(NULL, size, PROT_READ | PROT_WRITE,
						MAP_SHARED, fd, 0);
			else if (r == EBADF || r == EFBIG || r == ENOSPC || r == EIO)
				return -r;
		}
		bufsz = min(bufsz, 2*1024*1024);
		buf = mmapbase;
	}
	if (mmapbase == MAP_FAILED) {
		if (!splice_buffer) splice_buffer = malloc(256*1024);
		buf = splice_buffer;
		if (!buf) return -ENOMEM;
		bufsz = min(bufsz, 256*1024);
	}

	while (done < size) {
		if (cb != NULL) cb(cb_ctx, done);

		togo = min(size - done, bufsz);
		r = apk_istream_read(is, buf, togo);
		if (r <= 0) {
			if (r) goto err;
			if (size != APK_IO_ALL && done != size) {
				r = -EBADMSG;
				goto err;
			}
			break;
		}

		if (mmapbase == MAP_FAILED) {
			if (write(fd, buf, r) != r) {
				if (r < 0)
					r = -errno;
				goto err;
			}
		} else
			buf += r;

		done += r;
	}
	r = done;
err:
	if (mmapbase != MAP_FAILED)
		munmap(mmapbase, size);
	return r;
}

int apk_blob_from_istream(struct apk_istream *is, size_t size, apk_blob_t *b)
{
	void *ptr;
	ssize_t rsize;

	*b = APK_BLOB_NULL;

	ptr = malloc(size);
	if (!ptr) return -ENOMEM;

	rsize = apk_istream_read(is, ptr, size);
	if (rsize < 0) {
		free(ptr);
		return rsize;
	}
	if (rsize != size)
		ptr = realloc(ptr, rsize);

	*b = APK_BLOB_PTR_LEN(ptr, rsize);
	return 0;
}

int apk_blob_from_file(int atfd, const char *file, apk_blob_t *b)
{
	struct stat st;
	char *buf;
	ssize_t n;
	int fd;

	*b = APK_BLOB_NULL;

	if (atfd_error(atfd)) return atfd;

	fd = openat(atfd, file, O_RDONLY | O_CLOEXEC);
	if (fd < 0) goto err;
	if (fstat(fd, &st) < 0) goto err_fd;

	buf = malloc(st.st_size);
	if (!buf) goto err_fd;

	n = read(fd, buf, st.st_size);
	if (n != st.st_size) {
		if (n >= 0) errno = EIO;
		goto err_read;
	}

	close(fd);
	*b = APK_BLOB_PTR_LEN(buf, st.st_size);
	return 0;

err_read:
	free(buf);
err_fd:
	close(fd);
err:
	return -errno;
}

int apk_blob_to_file(int atfd, const char *file, apk_blob_t b, unsigned int flags)
{
	int fd, r, len;

	if (atfd_error(atfd)) return atfd;

	fd = openat(atfd, file, O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
	if (fd < 0)
		return -errno;

	len = b.len;
	r = write(fd, b.ptr, len);
	if ((r == len) &&
	    (flags & APK_BTF_ADD_EOL) && (b.len == 0 || b.ptr[b.len-1] != '\n')) {
		len = 1;
		r = write(fd, "\n", len);
	}

	if (r < 0)
		r = -errno;
	else if (r != len)
		r = -ENOSPC;
	else
		r = 0;
	close(fd);

	if (r != 0)
		unlinkat(atfd, file, 0);

	return r;
}

static int cmp_xattr(const void *p1, const void *p2)
{
	const struct apk_xattr *d1 = p1, *d2 = p2;
	return strcmp(d1->name, d2->name);
}

static void hash_len_data(EVP_MD_CTX *ctx, uint32_t len, const void *ptr)
{
	uint32_t belen = htobe32(len);
	EVP_DigestUpdate(ctx, &belen, sizeof(belen));
	EVP_DigestUpdate(ctx, ptr, len);
}

void apk_fileinfo_hash_xattr_array(struct apk_xattr_array *xattrs, const EVP_MD *md, struct apk_checksum *csum)
{
	struct apk_xattr *xattr;
	EVP_MD_CTX *mdctx;

	if (!xattrs || xattrs->num == 0) goto err;
	mdctx = EVP_MD_CTX_new();
	if (!mdctx) goto err;

	qsort(xattrs->item, xattrs->num, sizeof(xattrs->item[0]), cmp_xattr);

	EVP_DigestInit_ex(mdctx, md, NULL);
	foreach_array_item(xattr, xattrs) {
		hash_len_data(mdctx, strlen(xattr->name), xattr->name);
		hash_len_data(mdctx, xattr->value.len, xattr->value.ptr);
	}
	csum->type = EVP_MD_CTX_size(mdctx);
	EVP_DigestFinal_ex(mdctx, csum->data, NULL);
	EVP_MD_CTX_free(mdctx);
	return;
err:
	csum->type = APK_CHECKSUM_NONE;
}

void apk_fileinfo_hash_xattr(struct apk_file_info *fi)
{
	apk_fileinfo_hash_xattr_array(fi->xattrs, apk_checksum_default(), &fi->xattr_csum);
}

int apk_fileinfo_get(int atfd, const char *filename, unsigned int flags,
		     struct apk_file_info *fi, struct apk_atom_pool *atoms)
{
	struct stat st;
	unsigned int checksum = flags & 0xff;
	unsigned int xattr_checksum = (flags >> 8) & 0xff;
	int atflags = 0;

	if (atfd_error(atfd)) return atfd;

	memset(fi, 0, sizeof *fi);
	if (flags & APK_FI_NOFOLLOW)
		atflags |= AT_SYMLINK_NOFOLLOW;

	if (fstatat(atfd, filename, &st, atflags) != 0)
		return -errno;

	*fi = (struct apk_file_info) {
		.size = st.st_size,
		.uid = st.st_uid,
		.gid = st.st_gid,
		.mode = st.st_mode,
		.mtime = st.st_mtime,
		.device = st.st_rdev,
	};

	if (xattr_checksum != APK_CHECKSUM_NONE && !S_ISLNK(fi->mode) && !S_ISFIFO(fi->mode)) {
		ssize_t len, vlen;
		int fd, i, r;
		char val[1024], buf[1024];

		r = 0;
		fd = openat(atfd, filename, O_RDONLY|O_NONBLOCK);
		if (fd >= 0) {
			len = flistxattr(fd, buf, sizeof(buf));
			if (len > 0) {
				struct apk_xattr_array *xattrs = NULL;
				apk_xattr_array_init(&xattrs);
				for (i = 0; i < len; i += strlen(&buf[i]) + 1) {
					vlen = fgetxattr(fd, &buf[i], val, sizeof(val));
					if (vlen < 0) {
						r = errno;
						if (r == ENODATA) continue;
						break;
					}
					*apk_xattr_array_add(&xattrs) = (struct apk_xattr) {
						.name = &buf[i],
						.value = *apk_atomize_dup(atoms, APK_BLOB_PTR_LEN(val, vlen)),
					};
				}
				apk_fileinfo_hash_xattr_array(xattrs, apk_checksum_evp(xattr_checksum), &fi->xattr_csum);
				apk_xattr_array_free(&xattrs);
			} else if (r < 0) r = errno;
			close(fd);
		} else r = errno;

		if (r && r != ENOTSUP) return -r;
	}

	if (checksum == APK_CHECKSUM_NONE) return 0;
	if (S_ISDIR(st.st_mode)) return 0;

	/* Checksum file content */
	if ((flags & APK_FI_NOFOLLOW) && S_ISLNK(st.st_mode)) {
		char target[PATH_MAX];
		if (st.st_size > sizeof target) return -ENOMEM;
		if (readlinkat(atfd, filename, target, st.st_size) < 0)
			return -errno;
		EVP_Digest(target, st.st_size, fi->csum.data, NULL,
			   apk_checksum_evp(checksum), NULL);
		fi->csum.type = checksum;
	} else {
		struct apk_istream *is = apk_istream_from_file(atfd, filename);
		if (!IS_ERR_OR_NULL(is)) {
			EVP_MD_CTX *mdctx;
			apk_blob_t blob;

			mdctx = EVP_MD_CTX_new();
			if (mdctx) {
				EVP_DigestInit_ex(mdctx, apk_checksum_evp(checksum), NULL);
				if (is->flags & APK_ISTREAM_SINGLE_READ)
					EVP_MD_CTX_set_flags(mdctx, EVP_MD_CTX_FLAG_ONESHOT);
				while (!APK_BLOB_IS_NULL(blob = apk_istream_get_all(is)))
					EVP_DigestUpdate(mdctx, (void*) blob.ptr, blob.len);
				fi->csum.type = EVP_MD_CTX_size(mdctx);
				EVP_DigestFinal_ex(mdctx, fi->csum.data, NULL);
				EVP_MD_CTX_free(mdctx);
			}
			apk_istream_close(is);
		}
	}

	return 0;
}

void apk_fileinfo_free(struct apk_file_info *fi)
{
	apk_xattr_array_free(&fi->xattrs);
}

int apk_dir_foreach_file(int dirfd, apk_dir_file_cb cb, void *ctx)
{
	struct dirent *de;
	DIR *dir;
	int ret = 0;

	if (dirfd < 0)
		return -1;

	dir = fdopendir(dirfd);
	if (!dir) {
		close(dirfd);
		return -1;
	}

	/* We get called here with dup():ed fd. Since they all refer to
	 * same object, we need to rewind so subsequent calls work. */
	rewinddir(dir);

	while ((de = readdir(dir)) != NULL) {
		if (de->d_name[0] == '.') {
			if (de->d_name[1] == 0 ||
			    (de->d_name[1] == '.' && de->d_name[2] == 0))
				continue;
		}
		ret = cb(ctx, dirfd, de->d_name);
		if (ret) break;
	}
	closedir(dir);
	return ret;
}

struct apk_istream *apk_istream_from_file_gz(int atfd, const char *file)
{
	return apk_istream_gunzip(apk_istream_from_file(atfd, file));
}

struct apk_fd_ostream {
	struct apk_ostream os;
	int fd, rc;

	const char *file, *tmpfile;
	int atfd;

	size_t bytes;
	char buffer[1024];
};

static ssize_t safe_write(int fd, const void *ptr, size_t size)
{
	ssize_t i = 0, r;

	while (i < size) {
		r = write(fd, ptr + i, size - i);
		if (r < 0)
			return -errno;
		if (r == 0)
			return i;
		i += r;
	}

	return i;
}

static ssize_t fdo_flush(struct apk_fd_ostream *fos)
{
	ssize_t r;

	if (fos->bytes == 0)
		return 0;

	if ((r = safe_write(fos->fd, fos->buffer, fos->bytes)) != fos->bytes) {
		fos->rc = r < 0 ? r : -EIO;
		return r;
	}

	fos->bytes = 0;
	return 0;
}

static ssize_t fdo_write(struct apk_ostream *os, const void *ptr, size_t size)
{
	struct apk_fd_ostream *fos = container_of(os, struct apk_fd_ostream, os);
	ssize_t r;

	if (size + fos->bytes >= sizeof(fos->buffer)) {
		r = fdo_flush(fos);
		if (r != 0)
			return r;
		if (size >= sizeof(fos->buffer) / 2) {
			r = safe_write(fos->fd, ptr, size);
			if (r != size)
				fos->rc = r < 0 ? r : -EIO;
			return r;
		}
	}

	memcpy(&fos->buffer[fos->bytes], ptr, size);
	fos->bytes += size;

	return size;
}

static int fdo_close(struct apk_ostream *os)
{
	struct apk_fd_ostream *fos = container_of(os, struct apk_fd_ostream, os);
	int rc;

	fdo_flush(fos);
	rc = fos->rc;

	if (fos->fd > STDERR_FILENO &&
	    close(fos->fd) < 0)
		rc = -errno;

	if (fos->tmpfile != NULL) {
		if (rc == 0)
			renameat(fos->atfd, fos->tmpfile,
				 fos->atfd, fos->file);
		else
			unlinkat(fos->atfd, fos->tmpfile, 0);
	}

	free(fos);

	return rc;
}

static const struct apk_ostream_ops fd_ostream_ops = {
	.write = fdo_write,
	.close = fdo_close,
};

struct apk_ostream *apk_ostream_to_fd(int fd)
{
	struct apk_fd_ostream *fos;

	if (fd < 0) return ERR_PTR(-EBADF);

	fos = malloc(sizeof(struct apk_fd_ostream));
	if (fos == NULL) {
		close(fd);
		return ERR_PTR(-ENOMEM);
	}

	*fos = (struct apk_fd_ostream) {
		.os.ops = &fd_ostream_ops,
		.fd = fd,
	};

	return &fos->os;
}

struct apk_ostream *apk_ostream_to_file(int atfd,
					const char *file,
					const char *tmpfile,
					mode_t mode)
{
	struct apk_ostream *os;
	int fd;

	if (atfd_error(atfd)) return ERR_PTR(atfd);

	fd = openat(atfd, tmpfile ?: file, O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, mode);
	if (fd < 0) return ERR_PTR(-errno);

	fcntl(fd, F_SETFD, FD_CLOEXEC);

	os = apk_ostream_to_fd(fd);
	if (IS_ERR_OR_NULL(os)) return ERR_CAST(os);

	if (tmpfile != NULL) {
		struct apk_fd_ostream *fos =
			container_of(os, struct apk_fd_ostream, os);
		fos->file = file;
		fos->tmpfile = tmpfile;
		fos->atfd = atfd;
	}
	return os;
}

struct apk_counter_ostream {
	struct apk_ostream os;
	off_t *counter;
};

static ssize_t co_write(struct apk_ostream *os, const void *ptr, size_t size)
{
	struct apk_counter_ostream *cos = container_of(os, struct apk_counter_ostream, os);

	*cos->counter += size;
	return size;
}

static int co_close(struct apk_ostream *os)
{
	struct apk_counter_ostream *cos = container_of(os, struct apk_counter_ostream, os);

	free(cos);
	return 0;
}

static const struct apk_ostream_ops counter_ostream_ops = {
	.write = co_write,
	.close = co_close,
};

struct apk_ostream *apk_ostream_counter(off_t *counter)
{
	struct apk_counter_ostream *cos;

	cos = malloc(sizeof(struct apk_counter_ostream));
	if (cos == NULL)
		return NULL;

	*cos = (struct apk_counter_ostream) {
		.os.ops = &counter_ostream_ops,
		.counter = counter,
	};

	return &cos->os;
}

size_t apk_ostream_write_string(struct apk_ostream *os, const char *string)
{
	size_t len;

	len = strlen(string);
	if (apk_ostream_write(os, string, len) != len)
		return -1;

	return len;
}

struct cache_item {
	apk_hash_node hash_node;
	unsigned int genid;
	union {
		uid_t uid;
		gid_t gid;
	};
	unsigned short len;
	char name[];
};

static apk_blob_t cache_item_get_key(apk_hash_item item)
{
	struct cache_item *ci = (struct cache_item *) item;
	return APK_BLOB_PTR_LEN(ci->name, ci->len);
}

static const struct apk_hash_ops id_hash_ops = {
	.node_offset = offsetof(struct cache_item, hash_node),
	.get_key = cache_item_get_key,
	.hash_key = apk_blob_hash,
	.compare = apk_blob_compare,
	.delete_item = (apk_hash_delete_f) free,
};

static struct cache_item *resolve_cache_item(struct apk_hash *hash, apk_blob_t name)
{
	struct cache_item *ci;
	unsigned long h;

	h = id_hash_ops.hash_key(name);
	ci = (struct cache_item *) apk_hash_get_hashed(hash, name, h);
	if (ci != NULL)
		return ci;

	ci = calloc(1, sizeof(struct cache_item) + name.len);
	if (ci == NULL)
		return NULL;

	ci->len = name.len;
	memcpy(ci->name, name.ptr, name.len);
	apk_hash_insert_hashed(hash, ci, h);

	return ci;
}

void apk_id_cache_init(struct apk_id_cache *idc, int root_fd)
{
	idc->root_fd = root_fd;
	idc->genid = 1;
	apk_hash_init(&idc->uid_cache, &id_hash_ops, 256);
	apk_hash_init(&idc->gid_cache, &id_hash_ops, 256);
}

void apk_id_cache_free(struct apk_id_cache *idc)
{
	apk_hash_free(&idc->uid_cache);
	apk_hash_free(&idc->gid_cache);
}

void apk_id_cache_reset(struct apk_id_cache *idc)
{
	idc->genid++;
	if (idc->genid == 0)
		idc->genid = 1;
}

static FILE *fopenat(int dirfd, const char *pathname)
{
	FILE *f;
	int fd;

	fd = openat(dirfd, pathname, O_RDONLY|O_CLOEXEC);
	if (fd < 0) return NULL;

	f = fdopen(fd, "r");
	if (!f) close(fd);
	return f;
}

uid_t apk_resolve_uid(struct apk_id_cache *idc, apk_blob_t username, uid_t default_uid)
{
#ifdef HAVE_FGETPWENT_R
	char buf[1024];
	struct passwd pwent;
#endif
	struct cache_item *ci;
	struct passwd *pwd;
	FILE *in;

	ci = resolve_cache_item(&idc->uid_cache, username);
	if (ci == NULL)
		return default_uid;

	if (ci->genid != idc->genid) {
		ci->genid = idc->genid;
		ci->uid = -1;

		in = fopenat(idc->root_fd, "etc/passwd");
		if (in) {
			do {
#ifdef HAVE_FGETPWENT_R
				fgetpwent_r(in, &pwent, buf, sizeof(buf), &pwd);
#else
				pwd = fgetpwent(in);
#endif
				if (pwd == NULL)
					break;
				if (apk_blob_compare(APK_BLOB_STR(pwd->pw_name), username) == 0) {
					ci->uid = pwd->pw_uid;
					break;
				}
			} while (1);
			fclose(in);
		}
	}

	if (ci->uid != -1)
		return ci->uid;

	return default_uid;
}

uid_t apk_resolve_gid(struct apk_id_cache *idc, apk_blob_t groupname, uid_t default_gid)
{
#ifdef HAVE_FGETGRENT_R
	char buf[1024];
	struct group grent;
#endif
	struct cache_item *ci;
	struct group *grp;
	FILE *in;

	ci = resolve_cache_item(&idc->gid_cache, groupname);
	if (ci == NULL)
		return default_gid;

	if (ci->genid != idc->genid) {
		ci->genid = idc->genid;
		ci->gid = -1;

		in = fopenat(idc->root_fd, "etc/group");
		if (in) {
			do {
#ifdef HAVE_FGETGRENT_R
				fgetgrent_r(in, &grent, buf, sizeof(buf), &grp);
#else
				grp = fgetgrent(in);
#endif
				if (grp == NULL)
					break;
				if (apk_blob_compare(APK_BLOB_STR(grp->gr_name), groupname) == 0) {
					ci->gid = grp->gr_gid;
					break;
				}
			} while (1);
			fclose(in);
		}
	}

	if (ci->gid != -1)
		return ci->gid;

	return default_gid;
}
