/* apk_archive.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2005-2008 Natanael Copa <n@tanael.org>
 * Copyright (C) 2008-2011 Timo Teräs <timo.teras@iki.fi>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef APK_ARCHIVE
#define APK_ARCHIVE

#include <sys/types.h>
#include "apk_blob.h"
#include "apk_io.h"

#define APK_EXTRACTF_NO_CHOWN	0x0001

typedef int (*apk_archive_entry_parser)(void *ctx,
					const struct apk_file_info *ae,
					struct apk_istream *istream);

int apk_tar_parse(struct apk_istream *,
		  apk_archive_entry_parser parser, void *ctx,
		  struct apk_id_cache *);
int apk_tar_write_entry(struct apk_ostream *, const struct apk_file_info *ae,
			const char *data);
int apk_tar_write_padding(struct apk_ostream *, const struct apk_file_info *ae);

int apk_archive_entry_extract(int atfd, const struct apk_file_info *ae,
			      const char *extract_name, const char *hardlink_name,
			      struct apk_istream *is,
			      apk_progress_cb cb, void *cb_ctx,
			      unsigned int extract_flags);

#endif
