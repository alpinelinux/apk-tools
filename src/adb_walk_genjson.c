#include "adb.h"
#include "apk_print.h"

struct adb_walk_genjson {
	int nest, indent;
	unsigned int key_printed : 1;
	unsigned int need_separator : 1;
	unsigned int need_newline : 1;
	char end[ADB_WALK_MAX_NESTING];
};

static struct adb_walk_genjson *walk_genjson_ctx(struct adb_walk *walk)
{
	static_assert(sizeof walk->ctx >= sizeof(struct adb_walk_genjson), "buffer size mismatch");
	return (struct adb_walk_genjson *) &walk->ctx[0];
}

static void adb_walk_genjson_indent(struct adb_walk *d, bool item)
{
	static char pad[] = "\n                                ";
	struct adb_walk_genjson *dt = walk_genjson_ctx(d);

	if (dt->key_printed) {
		apk_ostream_write_blob(d->os, APK_BLOB_STRLIT(" "));
	} else {
		if (item && dt->need_separator) apk_ostream_write_blob(d->os, APK_BLOB_STRLIT(","));
		if (dt->need_newline) {
			assert(sizeof pad >= 2*dt->indent);
			apk_ostream_write(d->os, pad, 1 + 2*dt->indent);
		} else {
			apk_ostream_write_blob(d->os, APK_BLOB_STRLIT(" "));
		}
	}
	dt->key_printed = 0;
}

static void adb_walk_genjson_start_indent(struct adb_walk *d, char start_brace, char end_brace)
{
	struct adb_walk_genjson *dt = walk_genjson_ctx(d);

	assert(dt->nest < ARRAY_SIZE(dt->end));
	if (start_brace) apk_ostream_write_blob(d->os, APK_BLOB_PTR_LEN(&start_brace, 1));
	dt->end[++dt->nest] = end_brace;
	if (end_brace) dt->indent++;
	dt->need_separator = 0;
	dt->need_newline = 1;
}

static int adb_walk_genjson_start_schema(struct adb_walk *d, uint32_t schema_id)
{
	struct adb_walk_genjson *dt = walk_genjson_ctx(d);

	if (dt->nest == 0)
		adb_walk_genjson_start_indent(d, '{', '}');
	else	adb_walk_genjson_start_indent(d, 0, 0);

	return 0;
}

static int adb_walk_genjson_start_array(struct adb_walk *d, unsigned int num)
{
	adb_walk_genjson_indent(d, true);
	adb_walk_genjson_start_indent(d, '[', ']');
	return 0;
}

static int adb_walk_genjson_start_object(struct adb_walk *d)
{
	adb_walk_genjson_indent(d, true);
	adb_walk_genjson_start_indent(d, '{', '}');
	return 0;
}

static int adb_walk_genjson_end(struct adb_walk *d)
{
	struct adb_walk_genjson *dt = walk_genjson_ctx(d);

	dt->need_newline = 1;
	if (dt->end[dt->nest]) {
		dt->indent--;
		adb_walk_genjson_indent(d, false);
		apk_ostream_write_blob(d->os, APK_BLOB_PTR_LEN(&dt->end[dt->nest], 1));
		dt->end[dt->nest] = 0;
	}
	dt->nest--;
	dt->need_separator = 1;
	dt->need_newline = 0;
	return 0;
}

static int adb_walk_genjson_comment(struct adb_walk *d, apk_blob_t comment)
{
	// JSON is data only and does not allow comments
	return 0;
}

static int adb_walk_genjson_key(struct adb_walk *d, apk_blob_t key)
{
	struct adb_walk_genjson *dt = walk_genjson_ctx(d);

	if (!APK_BLOB_IS_NULL(key)) {
		dt->need_newline = 1;
		adb_walk_genjson_indent(d, true);
		apk_ostream_write_blob(d->os, APK_BLOB_STRLIT("\""));
		apk_ostream_write_blob(d->os, key);
		apk_ostream_write_blob(d->os, APK_BLOB_STRLIT("\":"));
		dt->key_printed = 1;
		dt->need_separator = 1;
	}
	return 0;
}

static int adb_walk_genjson_string(struct adb_walk *d, apk_blob_t val, int multiline)
{
	struct adb_walk_genjson *dt = walk_genjson_ctx(d);
	char esc[2] = "\\ ";
	int done = 0;

	dt->need_newline = 1;
	adb_walk_genjson_indent(d, true);
	apk_ostream_write_blob(d->os, APK_BLOB_STRLIT("\""));
	for (int i = 0; i < val.len; i++) {
		char ch = val.ptr[i];
		switch (ch) {
		case '"': esc[1] = '"'; break;
		case '\n': esc[1] = 'n'; break;
		case '\t': esc[1] = 't'; break;
		case '\\': esc[1] = '\\'; break;
		default: continue;
		}
		if (i != done) apk_ostream_write(d->os, &val.ptr[done], i - done);
		apk_ostream_write(d->os, esc, sizeof esc);
		done = i+1;
	}
	if (done < val.len) apk_ostream_write(d->os, &val.ptr[done], val.len - done);
	apk_ostream_write_blob(d->os, APK_BLOB_STRLIT("\""));
	dt->need_separator = 1;
	return 0;
}

static int adb_walk_genjson_numeric(struct adb_walk *d, uint64_t val, int octal)
{
	struct adb_walk_genjson *dt = walk_genjson_ctx(d);

	dt->need_newline = 1;
	adb_walk_genjson_indent(d, true);
	apk_ostream_fmt(d->os, "%llu", val);
	dt->need_separator = 1;
	return 0;
}

const struct adb_walk_ops adb_walk_genjson_ops = {
	.start_schema = adb_walk_genjson_start_schema,
	.start_array = adb_walk_genjson_start_array,
	.start_object = adb_walk_genjson_start_object,
	.end = adb_walk_genjson_end,
	.comment = adb_walk_genjson_comment,
	.key = adb_walk_genjson_key,
	.string = adb_walk_genjson_string,
	.numeric = adb_walk_genjson_numeric,
};
