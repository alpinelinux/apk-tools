#include <errno.h>
#include <stdlib.h>
#include "apk_serialize.h"
#include "apk_io.h"

struct apk_serializer *_apk_serializer_init(const struct apk_serializer_ops *ops, struct apk_ostream *os, void *ctx)
{
	int r = -ENOMEM;

	if (IS_ERR(os)) return ERR_CAST(os);
	if (!ctx) {
		ctx = malloc(ops->context_size);
		if (!ctx) goto fail;
	}
	memset(ctx, 0, ops->context_size);

	*(struct apk_serializer *)ctx = (struct apk_serializer) {
		.ops = ops,
		.os = os,
	};
	if (ops->init) {
		r = ops->init(ctx);
		if (r < 0) goto fail;
	}
	return ctx;
fail:
	apk_ostream_close_error(os, r);
	return ERR_PTR(r);
}

void apk_serializer_cleanup(struct apk_serializer *ser)
{
	if (!ser) return;
	if (ser->os) apk_ostream_close(ser->os);
	if (ser->ops->cleanup) ser->ops->cleanup(ser);
	if (ser->ops->context_size >= 1024) free(ser);
}
