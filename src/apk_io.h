/* apk_io.h - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef APK_IO
#define APK_IO

#include <sys/types.h>
#include <fcntl.h>
#include <time.h>

#include "apk_defines.h"
#include "apk_blob.h"
#include "apk_atom.h"
#include "apk_crypto.h"

int apk_make_dirs(int root_fd, const char *dirname, mode_t dirmode, mode_t parentmode);
ssize_t apk_write_fully(int fd, const void *ptr, size_t size);

struct apk_id_hash {
	int empty;
	struct hlist_head by_id[16], by_name[16];
};

struct apk_id_cache {
	int root_fd;
	struct apk_id_hash uid_cache;
	struct apk_id_hash gid_cache;
};

struct apk_xattr {
	const char *name;
	apk_blob_t value;
};
APK_ARRAY(apk_xattr_array, struct apk_xattr);

struct apk_file_meta {
	time_t mtime, atime;
};

struct apk_file_info {
	const char *name;
	const char *link_target;
	const char *uname;
	const char *gname;
	off_t size;
	uid_t uid;
	gid_t gid;
	mode_t mode;
	time_t mtime;
	dev_t device;
	struct apk_digest digest;
	struct apk_digest xattr_digest;
	struct apk_xattr_array *xattrs;
};

extern size_t apk_io_bufsize;

struct apk_istream;
struct apk_ostream;

struct apk_istream_ops {
	void (*get_meta)(struct apk_istream *is, struct apk_file_meta *meta);
	ssize_t (*read)(struct apk_istream *is, void *ptr, size_t size);
	int (*close)(struct apk_istream *is);
};

#define APK_ISTREAM_SINGLE_READ			0x0001

struct apk_istream {
	uint8_t *ptr, *end, *buf;
	size_t buf_size;
	int err;
	unsigned int flags;
	const struct apk_istream_ops *ops;
};

typedef int (*apk_archive_entry_parser)(void *ctx,
					const struct apk_file_info *ae,
					struct apk_istream *istream);

#define APK_IO_ALL ((size_t)-1)

#define APK_ISTREAM_FORCE_REFRESH		((time_t) -1)

struct apk_istream *apk_istream_from_blob(struct apk_istream *, apk_blob_t);
struct apk_istream *__apk_istream_from_file(int atfd, const char *file, int try_mmap);
static inline struct apk_istream *apk_istream_from_file(int atfd, const char *file) { return __apk_istream_from_file(atfd, file, 0); }
static inline struct apk_istream *apk_istream_from_file_mmap(int atfd, const char *file) { return __apk_istream_from_file(atfd, file, 1); }
struct apk_istream *apk_istream_from_fd(int fd);
struct apk_istream *apk_istream_from_fd_url_if_modified(int atfd, const char *url, time_t since);
static inline int apk_istream_error(struct apk_istream *is, int err) { if (is->err >= 0 && err) is->err = err; return is->err < 0 ? is->err : 0; }
apk_blob_t apk_istream_mmap(struct apk_istream *is);
ssize_t apk_istream_read_max(struct apk_istream *is, void *ptr, size_t size);
int apk_istream_read(struct apk_istream *is, void *ptr, size_t size);
void *apk_istream_peek(struct apk_istream *is, size_t len);
void *apk_istream_get(struct apk_istream *is, size_t len);
int apk_istream_get_max(struct apk_istream *is, size_t size, apk_blob_t *data);
int apk_istream_get_delim(struct apk_istream *is, apk_blob_t token, apk_blob_t *data);
static inline int apk_istream_get_all(struct apk_istream *is, apk_blob_t *data) { return apk_istream_get_max(is, APK_IO_ALL, data); }
ssize_t apk_stream_copy(struct apk_istream *is, struct apk_ostream *os, size_t size,
			apk_progress_cb cb, void *cb_ctx, struct apk_digest_ctx *dctx);

static inline struct apk_istream *apk_istream_from_url(const char *url, time_t since)
{
	return apk_istream_from_fd_url_if_modified(AT_FDCWD, url, since);
}
static inline struct apk_istream *apk_istream_from_fd_url(int atfd, const char *url, time_t since)
{
	return apk_istream_from_fd_url_if_modified(atfd, url, since);
}
static inline void apk_istream_get_meta(struct apk_istream *is, struct apk_file_meta *meta)
{
	is->ops->get_meta(is, meta);
}
static inline int apk_istream_close(struct apk_istream *is)
{
	return is->ops->close(is);
}
static inline int apk_istream_close_error(struct apk_istream *is, int r)
{
	if (r < 0) apk_istream_error(is, r);
	return apk_istream_close(is);
}

struct apk_segment_istream {
	struct apk_istream is;
	struct apk_istream *pis;
	size_t bytes_left;
	time_t mtime;
};
struct apk_istream *apk_istream_segment(struct apk_segment_istream *sis, struct apk_istream *is, size_t len, time_t mtime);

struct apk_digest_istream {
	struct apk_istream is;
	struct apk_istream *pis;
	struct apk_digest *digest;
	struct apk_digest_ctx dctx;
	off_t size_left;
};
struct apk_istream *apk_istream_verify(struct apk_digest_istream *dis, struct apk_istream *is, off_t size, struct apk_digest *d);

#define APK_ISTREAM_TEE_COPY_META 1
#define APK_ISTREAM_TEE_OPTIONAL  2

struct apk_istream *apk_istream_tee(struct apk_istream *from, struct apk_ostream *to, int copy_meta,
				    apk_progress_cb cb, void *cb_ctx);

struct apk_ostream_ops {
	void (*set_meta)(struct apk_ostream *os, struct apk_file_meta *meta);
	int (*write)(struct apk_ostream *os, const void *buf, size_t size);
	int (*close)(struct apk_ostream *os);
};

struct apk_ostream {
	const struct apk_ostream_ops *ops;
	int rc;
};

struct apk_ostream *apk_ostream_counter(off_t *);
struct apk_ostream *apk_ostream_to_fd(int fd);
struct apk_ostream *apk_ostream_to_file(int atfd, const char *file, mode_t mode);
ssize_t apk_ostream_write_string(struct apk_ostream *os, const char *string);
void apk_ostream_copy_meta(struct apk_ostream *os, struct apk_istream *is);
static inline int apk_ostream_error(struct apk_ostream *os) { return os->rc; }
static inline int apk_ostream_cancel(struct apk_ostream *os, int rc) { if (!os->rc) os->rc = rc; return rc; }
static inline int apk_ostream_write(struct apk_ostream *os, const void *buf, size_t size) {
	return os->ops->write(os, buf, size);
}
static inline int apk_ostream_close(struct apk_ostream *os)
{
	int rc = os->rc;
	return os->ops->close(os) ?: rc;
}

int apk_blob_from_istream(struct apk_istream *is, size_t size, apk_blob_t *b);
int apk_blob_from_file(int atfd, const char *file, apk_blob_t *b);

#define APK_BTF_ADD_EOL		0x00000001
int apk_blob_to_file(int atfd, const char *file, apk_blob_t b, unsigned int flags);

#define APK_FI_NOFOLLOW		0x80000000
#define APK_FI_XATTR_DIGEST(x)	(((x) & 0xff) << 8)
#define APK_FI_XATTR_CSUM(x)	APK_FI_XATTR_DIGEST(apk_digest_alg_by_len(x))
#define APK_FI_DIGEST(x)	(((x) & 0xff))
#define APK_FI_CSUM(x)		APK_FI_DIGEST(apk_digest_alg_by_len(x))
int apk_fileinfo_get(int atfd, const char *filename, unsigned int flags,
		     struct apk_file_info *fi, struct apk_atom_pool *atoms);
void apk_fileinfo_hash_xattr(struct apk_file_info *fi, uint8_t alg);
void apk_fileinfo_free(struct apk_file_info *fi);

typedef int apk_dir_file_cb(void *ctx, int dirfd, const char *entry);
int apk_dir_foreach_file(int dirfd, apk_dir_file_cb cb, void *ctx);

const char *apk_url_local_file(const char *url);

void apk_id_cache_init(struct apk_id_cache *idc, int root_fd);
void apk_id_cache_free(struct apk_id_cache *idc);
void apk_id_cache_reset(struct apk_id_cache *idc);
uid_t apk_id_cache_resolve_uid(struct apk_id_cache *idc, apk_blob_t username, uid_t default_uid);
gid_t apk_id_cache_resolve_gid(struct apk_id_cache *idc, apk_blob_t groupname, gid_t default_gid);
apk_blob_t apk_id_cache_resolve_user(struct apk_id_cache *idc, uid_t uid);
apk_blob_t apk_id_cache_resolve_group(struct apk_id_cache *idc, gid_t gid);

// Gzip support

#define APK_MPART_DATA		1 /* data processed so far */
#define APK_MPART_BOUNDARY	2 /* final part of data, before boundary */
#define APK_MPART_END		3 /* signals end of stream */

typedef int (*apk_multipart_cb)(void *ctx, int part, apk_blob_t data);

struct apk_istream *apk_istream_zlib(struct apk_istream *, int,
				     apk_multipart_cb cb, void *ctx);
static inline struct apk_istream *apk_istream_gunzip_mpart(struct apk_istream *is,
					     apk_multipart_cb cb, void *ctx) {
	return apk_istream_zlib(is, 0, cb, ctx);
}
static inline struct apk_istream *apk_istream_gunzip(struct apk_istream *is) {
	return apk_istream_zlib(is, 0, NULL, NULL);
}
static inline struct apk_istream *apk_istream_deflate(struct apk_istream *is) {
	return apk_istream_zlib(is, 1, NULL, NULL);
}

struct apk_ostream *apk_ostream_zlib(struct apk_ostream *, int, uint8_t);
static inline struct apk_ostream *apk_ostream_gzip(struct apk_ostream *os) {
	return apk_ostream_zlib(os, 0, 0);
}
static inline struct apk_ostream *apk_ostream_deflate(struct apk_ostream *os, uint8_t level) {
	return apk_ostream_zlib(os, 1, level);
}

struct apk_istream *apk_istream_zstd(struct apk_istream *);
struct apk_ostream *apk_ostream_zstd(struct apk_ostream *, uint8_t);

#endif
