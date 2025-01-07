#include "adb.h"
#include "apk_print.h"

struct adb_walk_gentext {
	int nest;
	unsigned int line_started : 1;
	unsigned int key_printed : 1;
};

static struct adb_walk_gentext *walk_gentext_ctx(struct adb_walk *walk)
{
	static_assert(sizeof walk->ctx >= sizeof(struct adb_walk_gentext), "buffer size mismatch");
	return (struct adb_walk_gentext *) &walk->ctx[0];
}

static void adb_walk_gentext_indent(struct adb_walk *d)
{
	static char pad[] = "                                ";
	struct adb_walk_gentext *dt = walk_gentext_ctx(d);

	if (!dt->line_started) {
		assert(sizeof pad >= 2*dt->nest);
		apk_ostream_write(d->os, pad, 2*dt->nest);
	} else {
		apk_ostream_write_blob(d->os, APK_BLOB_STRLIT(" "));
	}
	dt->line_started = 1;
}

static void adb_walk_gentext_newline(struct adb_walk_gentext *dt)
{
	dt->line_started = 0;
	dt->key_printed = 0;
}

static int adb_walk_gentext_schema(struct adb_walk *d, uint32_t schema_id)
{
	struct adb_walk_gentext *dt = walk_gentext_ctx(d);

	adb_walk_gentext_indent(d);
	apk_ostream_fmt(d->os, "#%%SCHEMA: %08X\n", schema_id);
	adb_walk_gentext_newline(dt);
	return 0;
}

static int adb_walk_gentext_comment(struct adb_walk *d, apk_blob_t comment)
{
	struct adb_walk_gentext *dt = walk_gentext_ctx(d);

	adb_walk_gentext_indent(d);
	apk_ostream_write_blob(d->os, APK_BLOB_STRLIT("# "));
	apk_ostream_write_blob(d->os, comment);
	apk_ostream_write_blob(d->os, APK_BLOB_STRLIT("\n"));
	adb_walk_gentext_newline(dt);
	return 0;
}

static int adb_walk_gentext_start_array(struct adb_walk *d, unsigned int num)
{
	struct adb_walk_gentext *dt = walk_gentext_ctx(d);

	adb_walk_gentext_indent(d);
	apk_ostream_fmt(d->os, "# %d items\n", num);
	adb_walk_gentext_newline(dt);
	dt->nest++;
	return 0;
}

static int adb_walk_gentext_start_object(struct adb_walk *d)
{
	struct adb_walk_gentext *dt = walk_gentext_ctx(d);

	dt->nest++;
	return 0;
}

static int adb_walk_gentext_end(struct adb_walk *d)
{
	struct adb_walk_gentext *dt = walk_gentext_ctx(d);

	if (dt->line_started) {
		adb_walk_gentext_indent(d);
		apk_ostream_write_blob(d->os, APK_BLOB_STRLIT("# empty object\n"));
		adb_walk_gentext_newline(dt);
	}
	dt->nest--;
	return 0;
}

static int adb_walk_gentext_key(struct adb_walk *d, apk_blob_t key)
{
	struct adb_walk_gentext *dt = walk_gentext_ctx(d);

	if (!APK_BLOB_IS_NULL(key)) {
		if (dt->key_printed) {
			apk_ostream_write_blob(d->os, APK_BLOB_STRLIT("\n"));
			adb_walk_gentext_newline(dt);
		}
		adb_walk_gentext_indent(d);
		apk_ostream_write_blob(d->os, key);
		apk_ostream_write_blob(d->os, APK_BLOB_STRLIT(":"));
		dt->key_printed = 1;
	} else {
		adb_walk_gentext_indent(d);
		apk_ostream_write_blob(d->os, APK_BLOB_STRLIT("-"));
	}
	return 0;
}

static int need_quoting(apk_blob_t b)
{
	if (!b.len) return 0;
	// must not start with indicator character
	if (strchr("-?:,[]{}#&*!|>'\"%@`", b.ptr[0])) return 1;
	// must not contain ": " or " #"
	for (int i = 1; i < b.len-1; i++) {
		if (b.ptr[i] == '#') return 1;
		if (b.ptr[i] != ' ') continue;
		if (b.ptr[i-1] == ':') return 1;
	}
	return 0;
}

static int adb_walk_gentext_scalar(struct adb_walk *d, apk_blob_t scalar, int multiline)
{
	struct adb_walk_gentext *dt = walk_gentext_ctx(d);
	apk_blob_t nl = APK_BLOB_STR("\n");

	adb_walk_gentext_indent(d);

	if (scalar.len >= 60 || multiline || need_quoting(scalar)) {
		/* long or multiline */
		apk_blob_t l;

		apk_ostream_write_blob(d->os, APK_BLOB_STRLIT("|\n"));
		adb_walk_gentext_newline(dt);

		dt->nest++;
		while (apk_blob_split(scalar, nl, &l, &scalar)) {
			adb_walk_gentext_indent(d);
			apk_ostream_write_blob(d->os, l);
			apk_ostream_write_blob(d->os, APK_BLOB_STRLIT("\n"));
			adb_walk_gentext_newline(dt);
		}
		if (scalar.len) {
			adb_walk_gentext_indent(d);
			apk_ostream_write_blob(d->os, scalar);
			apk_ostream_write_blob(d->os, APK_BLOB_STRLIT("\n"));
			adb_walk_gentext_newline(dt);
		}
		dt->nest--;
	} else {
		apk_ostream_write_blob(d->os, scalar);
		apk_ostream_write_blob(d->os, APK_BLOB_STRLIT("\n"));
		adb_walk_gentext_newline(dt);
	}
	return 0;
}

const struct adb_walk_ops adb_walk_gentext_ops = {
	.schema = adb_walk_gentext_schema,
	.comment = adb_walk_gentext_comment,
	.start_array = adb_walk_gentext_start_array,
	.start_object = adb_walk_gentext_start_object,
	.end = adb_walk_gentext_end,
	.key = adb_walk_gentext_key,
	.scalar = adb_walk_gentext_scalar,
};
