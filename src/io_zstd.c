/* io_zstd.c - Alpine Package Keeper (APK)
 *
 * Copyright (C) 2008-2023 Timo Teräs <timo.teras@iki.fi>
 * Copyright (C) 2023 q66 <q66@chimera-linux.org>
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <zstd.h>

#include "apk_defines.h"
#include "apk_io.h"
#include "apk_nproc.h"

struct apk_zstd_istream {
	struct apk_istream is;
	struct apk_istream *input;
	ZSTD_DCtx *ctx;
	void *buf_in;
	size_t buf_insize;
	ZSTD_inBuffer inp;
};

static void zi_get_meta(struct apk_istream *input, struct apk_file_meta *meta)
{
	struct apk_zstd_istream *is = container_of(input, struct apk_zstd_istream, is);
	apk_istream_get_meta(is->input, meta);
}

static ssize_t zi_read(struct apk_istream *input, void *ptr, size_t size)
{
	struct apk_zstd_istream *is = container_of(input, struct apk_zstd_istream, is);
	uint8_t *cptr = ptr;

	while (size) {
		/* read next chunk */
		if (is->inp.pos == 0 || is->inp.pos >= is->inp.size) {
			ssize_t rs = apk_istream_read_max(is->input, is->buf_in, is->buf_insize);
			if (rs < 0) {
				is->is.err = rs;
				goto ret;
			} else if (rs == 0) {
				/* eof */
				is->is.err = 1;
				goto ret;
			}
			is->inp.size = rs;
			is->inp.pos = 0;
		}
		while (is->inp.pos < is->inp.size) {
			ZSTD_outBuffer outp = {cptr, size, 0};
			size_t ret = ZSTD_decompressStream(is->ctx, &outp, &is->inp);
			if (ZSTD_isError(ret)) {
				is->is.err = -EIO;
				goto ret;
			}
			cptr += outp.pos;
			size -= outp.pos;
			/* no more space in the buffer; leave the rest for next time */
			if (!size) goto ret;
		}
	}

ret:
	return cptr - (uint8_t *)ptr;
}

static int zi_close(struct apk_istream *input)
{
	int r;
	struct apk_zstd_istream *is = container_of(input, struct apk_zstd_istream, is);

	ZSTD_freeDCtx(is->ctx);
	r = apk_istream_close_error(is->input, is->is.err);
	free(is);
	return r;
}

static const struct apk_istream_ops zstd_istream_ops = {
	.get_meta = zi_get_meta,
	.read = zi_read,
	.close = zi_close,
};

struct apk_istream *apk_istream_zstd(struct apk_istream *input)
{
	struct apk_zstd_istream *is;
	size_t buf_insize;

	if (IS_ERR(input)) return ERR_CAST(input);

	buf_insize = ZSTD_DStreamInSize();

	is = malloc(sizeof(struct apk_zstd_istream) + apk_io_bufsize + buf_insize);
	if (is == NULL) goto err;

	is->buf_in = (uint8_t*)(is + 1) + apk_io_bufsize;
	is->buf_insize = buf_insize;
	is->inp.size = is->inp.pos = 0;
	is->inp.src = is->buf_in;

	if ((is->ctx = ZSTD_createDCtx()) == NULL) {
		free(is);
		goto err;
	}

	memset(&is->is, 0, sizeof(is->is));

	is->is.ops = &zstd_istream_ops;
	is->is.buf = (uint8_t*)(is + 1);
	is->is.buf_size = apk_io_bufsize;
	is->input = input;

	return &is->is;
err:
	return ERR_PTR(apk_istream_close_error(input, -ENOMEM));
}

struct apk_zstd_ostream {
	struct apk_ostream os;
	struct apk_ostream *output;
	ZSTD_CCtx *ctx;
	void *buf_out;
	size_t buf_outsize;
};

static int zo_write(struct apk_ostream *output, const void *ptr, size_t size)
{
	struct apk_zstd_ostream *os = container_of(output, struct apk_zstd_ostream, os);
	ssize_t r;
	ZSTD_inBuffer inp = {ptr, size, 0};

	do {
		ZSTD_outBuffer outp = {os->buf_out, os->buf_outsize, 0};
		size_t rem = ZSTD_compressStream2(os->ctx, &outp, &inp, ZSTD_e_continue);

		if (ZSTD_isError(rem))
			return apk_ostream_cancel(os->output, -EIO);

		if (outp.pos != 0) {
			r = apk_ostream_write(os->output, os->buf_out, outp.pos);
			if (r < 0) return r;
		}
	} while (inp.pos != inp.size);

	return 0;
}

static int zo_close(struct apk_ostream *output)
{
	struct apk_zstd_ostream *os = container_of(output, struct apk_zstd_ostream, os);
	ZSTD_inBuffer inp = {NULL, 0, 0};
	size_t rem;
	int r, rc = output->rc;

	do {
		ZSTD_outBuffer outp = {os->buf_out, os->buf_outsize, 0};
		rem = ZSTD_compressStream2(os->ctx, &outp, &inp, ZSTD_e_end);

		if (ZSTD_isError(rem)) break;

		if (outp.pos && apk_ostream_write(os->output, os->buf_out, outp.pos) < 0)
			break;
	} while (rem != 0);

	r = apk_ostream_close(os->output);
	ZSTD_freeCCtx(os->ctx);
	free(os);

	if (rc) return rc;
	if (ZSTD_isError(rem)) return 1;

	return r;
}

static const struct apk_ostream_ops zstd_ostream_ops = {
	.write = zo_write,
	.close = zo_close,
};

struct apk_ostream *apk_ostream_zstd(struct apk_ostream *output, uint8_t level)
{
	struct apk_zstd_ostream *os;
	size_t errc, buf_outsize;
	int threads;
	ZSTD_bounds bounds;

	if (IS_ERR(output)) return ERR_CAST(output);

	buf_outsize = ZSTD_CStreamOutSize();

	os = malloc(sizeof(struct apk_zstd_ostream) + buf_outsize);
	if (os == NULL) goto err;

	os->buf_outsize = buf_outsize;
	os->buf_out = (uint8_t*)(os + 1);

	if ((os->ctx = ZSTD_createCCtx()) == NULL) {
		free(os);
		goto err;
	}

	threads = apk_get_nproc();

	/* above 6 threads, zstd does not actually seem to perform much or at all
	 * better; it uses the cpu, it uses a disproportionate amount of memory,
	 * but time improvements are marginal at best
	 */
	if (threads > 6) threads = 6;

	/* constrain the thread count; e.g. static zstd does not support threads
	 * and will return 0 for both bounds, and setting compression level to
	 * any other number would actually fail, so avoid doing that
	 */
	bounds = ZSTD_cParam_getBounds(ZSTD_c_nbWorkers);
	if (threads < bounds.lowerBound) threads = bounds.lowerBound;
	if (threads > bounds.upperBound) threads = bounds.upperBound;

	errc = ZSTD_CCtx_setParameter(os->ctx, ZSTD_c_compressionLevel, level);
	if (ZSTD_isError(errc)) {
		free(os);
		goto err;
	}

	errc = ZSTD_CCtx_setParameter(os->ctx, ZSTD_c_nbWorkers, threads);
	if (ZSTD_isError(errc)) {
		free(os);
		goto err;
	}

	memset(&os->os, 0, sizeof(os->os));

	os->os.ops = &zstd_ostream_ops;
	os->output = output;

	return &os->os;
err:
	apk_ostream_close(output);
	return ERR_PTR(-ENOMEM);
}
