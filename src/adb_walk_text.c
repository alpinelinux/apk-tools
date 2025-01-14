#include <errno.h>
#include "adb.h"

//#define DEBUG_PRINT
#ifdef DEBUG_PRINT
#include <stdio.h>
#define dbg_printf(args...) fprintf(stderr, args)
#else
#define dbg_printf(args...)
#endif

int adb_walk_text(struct apk_istream *is, struct apk_ostream *os, const struct apk_serializer_ops *ops, struct apk_trust *trust)
{
	const apk_blob_t token = APK_BLOB_STR("\n");
	const apk_blob_t comment = APK_BLOB_STR(" #");
	const apk_blob_t key_sep = APK_BLOB_STR(": ");
	struct apk_serializer *ser;
	char mblockdata[1024*4];
	apk_blob_t l, comm, mblock = APK_BLOB_BUF(mblockdata);
	int r = 0, i, multi_line = 0, nesting = 0, new_item = 0;
	uint8_t started[64] = {0};

	ser = apk_serializer_init_alloca(ops, os);
	if (IS_ERR(ser)) {
		if (IS_ERR(is)) apk_istream_close(is);
		return PTR_ERR(ser);
	}
	if (IS_ERR(is)) {
		r = PTR_ERR(is);
		goto err;
	}
	ser->trust = trust;

	if (apk_istream_get_delim(is, token, &l) != 0) goto err;
	if (!apk_blob_pull_blob_match(&l, APK_BLOB_STR("#%SCHEMA: "))) goto err;
	if ((r = apk_ser_start_schema(ser, apk_blob_pull_uint(&l, 16))) != 0) goto err;

	started[0] = 1;
	while (apk_istream_get_delim(is, token, &l) == 0) {
		for (i = 0; l.len >= 2 && l.ptr[0] == ' ' && l.ptr[1] == ' '; i++, l.ptr += 2, l.len -= 2)
			if (multi_line && i >= multi_line) break;

		for (; nesting > i; nesting--) {
			if (multi_line) {
				apk_blob_t data = apk_blob_pushed(APK_BLOB_BUF(mblockdata), mblock);
				if (APK_BLOB_IS_NULL(data)) {
					r = -E2BIG;
					goto err;
				}
				if (data.len && data.ptr[data.len-1] == '\n') data.len--;
				dbg_printf("Multiline-Scalar >%d> "BLOB_FMT"\n", nesting, BLOB_PRINTF(data));
				if ((r = apk_ser_string(ser, data, 1)) != 0) goto err;
				mblock = APK_BLOB_BUF(mblockdata);
				multi_line = 0;
			}
			if (started[nesting]) {
				dbg_printf("End %d\n", nesting);
				if ((r = apk_ser_end(ser)) != 0) goto err;
			}
		}
		if (l.len >= 2 && l.ptr[0] == '-' && l.ptr[1] == ' ') {
			l.ptr += 2, l.len -= 2;
			if (!started[nesting]) {
				dbg_printf("Array %d\n", nesting);
				if ((r = apk_ser_start_array(ser, 0)) != 0) goto err;
				started[nesting] = 1;
			}
			new_item = 1;
		}
		dbg_printf(" >%d/%d< >"BLOB_FMT"<\n", nesting, i, BLOB_PRINTF(l));

		if (multi_line) {
			dbg_printf("Scalar-Block:>%d> "BLOB_FMT"\n", nesting, BLOB_PRINTF(l));
			apk_blob_push_blob(&mblock, l);
			apk_blob_push_blob(&mblock, APK_BLOB_STR("\n"));
			new_item = 0;
			continue;
		}

		if (l.len && l.ptr[0] == '#') {
			if ((r = apk_ser_comment(ser, l)) != 0) goto err;
			continue;
		}

		// contains ' #' -> comment
		if (!apk_blob_split(l, comment, &l, &comm))
			comm.len = 0;

		if (l.len) {
			apk_blob_t key = APK_BLOB_NULL, scalar = APK_BLOB_NULL;
			int start = 0;

			if (apk_blob_split(l, key_sep, &key, &scalar)) {
				// contains ': ' -> key + scalar
			} else if (l.ptr[l.len-1] == ':') {
				// ends ':' -> key + indented object/array
				key = APK_BLOB_PTR_LEN(l.ptr, l.len-1);
				start = 1;
			} else {
				scalar = l;
			}
			if (key.len) {
				if (new_item) {
					started[++nesting] = 0;
					dbg_printf("Array-Object %d\n", nesting);
				}
				if (!started[nesting]) {
					dbg_printf("Object %d\n", nesting);
					if ((r = apk_ser_start_object(ser)) != 0) goto err;
					started[nesting] = 1;
				}
				dbg_printf("Key >%d> "BLOB_FMT"\n", nesting, BLOB_PRINTF(key));
				if ((r = apk_ser_key(ser, key)) != 0) goto err;
				if (start) started[++nesting] = 0;
			}

			if (scalar.len) {
				if (scalar.ptr[0] == '|') {
					dbg_printf("Scalar-block >%d> "BLOB_FMT"\n", nesting, BLOB_PRINTF(scalar));
					// scalar '|' -> starts string literal block
					started[++nesting] = 0;
					multi_line = nesting;
				} else {
					if (scalar.ptr[0] == '\'') {
						dbg_printf("Scalar-squote >%d> "BLOB_FMT"\n", nesting, BLOB_PRINTF(scalar));
						if (scalar.len < 2 || scalar.ptr[scalar.len-1] != '\'') {
							r = -APKE_FORMAT_INVALID;
							goto err;
						}
						scalar.ptr ++;
						scalar.len -= 2;
					} else {
						dbg_printf("Scalar >%d> "BLOB_FMT"\n", nesting, BLOB_PRINTF(scalar));
					}
					if ((r = apk_ser_string(ser, scalar, 0)) != 0) goto err;
				}
			}
			new_item = 0;
		}

		if (comm.len) {
			if ((r = apk_ser_comment(ser, comm)) != 0) goto err;
		}

		dbg_printf(">%d> "BLOB_FMT"\n", nesting, BLOB_PRINTF(l));
	}
	apk_ser_end(ser);

err:
	apk_serializer_cleanup(ser);
	return apk_istream_close_error(is, r);
}
