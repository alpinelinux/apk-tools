#include "adb.h"
#include "apk_print.h"

struct serialize_yaml {
	struct apk_serializer ser;
	int nest, indent;
	unsigned int line_started : 1;
	unsigned int key_printed : 1;
	char end[APK_SERIALIZE_MAX_NESTING];
};

static void ser_yaml_indent(struct serialize_yaml *dt)
{
	static char pad[] = "                                ";

	if (!dt->line_started) {
		assert(sizeof pad >= 2*dt->indent);
		apk_ostream_write(dt->ser.os, pad, 2*dt->indent);
	} else {
		apk_ostream_write_blob(dt->ser.os, APK_BLOB_STRLIT(" "));
	}
	dt->line_started = 1;
}

static void ser_yaml_start_indent(struct serialize_yaml *dt, bool indent)
{
	assert(dt->nest < ARRAY_SIZE(dt->end));
	dt->end[++dt->nest] = indent;
	if (indent) dt->indent++;
}

static void ser_yaml_newline(struct serialize_yaml *dt)
{
	apk_ostream_write_blob(dt->ser.os, APK_BLOB_STRLIT("\n"));
	dt->line_started = 0;
	dt->key_printed = 0;
}

static int ser_yaml_start_schema(struct apk_serializer *ser, uint32_t schema_id)
{
	struct serialize_yaml *dt = container_of(ser, struct serialize_yaml, ser);

	ser_yaml_start_indent(dt, false);
	ser_yaml_indent(dt);
	apk_ostream_fmt(dt->ser.os, "#%%SCHEMA: %08X", schema_id);
	ser_yaml_newline(dt);
	return 0;
}

static int ser_yaml_start_array(struct apk_serializer *ser, unsigned int num)
{
	struct serialize_yaml *dt = container_of(ser, struct serialize_yaml, ser);

	ser_yaml_indent(dt);
	apk_ostream_fmt(dt->ser.os, "# %d items", num);
	ser_yaml_newline(dt);
	ser_yaml_start_indent(dt, true);
	return 0;
}

static int ser_yaml_start_object(struct apk_serializer *ser)
{
	struct serialize_yaml *dt = container_of(ser, struct serialize_yaml, ser);

	ser_yaml_start_indent(dt, true);
	return 0;
}

static int ser_yaml_end(struct apk_serializer *ser)
{
	struct serialize_yaml *dt = container_of(ser, struct serialize_yaml, ser);

	if (dt->line_started) {
		ser_yaml_indent(dt);
		apk_ostream_write_blob(dt->ser.os, APK_BLOB_STRLIT("# empty object"));
		ser_yaml_newline(dt);
	}
	if (dt->end[dt->nest]) dt->indent--;
	dt->nest--;
	return 0;
}

static int ser_yaml_comment(struct apk_serializer *ser, apk_blob_t comment)
{
	struct serialize_yaml *dt = container_of(ser, struct serialize_yaml, ser);

	ser_yaml_indent(dt);
	apk_ostream_write_blob(dt->ser.os, APK_BLOB_STRLIT("# "));
	apk_ostream_write_blob(dt->ser.os, comment);
	ser_yaml_newline(dt);
	return 0;
}

static int ser_yaml_key(struct apk_serializer *ser, apk_blob_t key)
{
	struct serialize_yaml *dt = container_of(ser, struct serialize_yaml, ser);

	if (!APK_BLOB_IS_NULL(key)) {
		if (dt->key_printed) ser_yaml_newline(dt);
		ser_yaml_indent(dt);
		apk_ostream_write_blob(dt->ser.os, key);
		apk_ostream_write_blob(dt->ser.os, APK_BLOB_STRLIT(":"));
		dt->key_printed = 1;
	} else {
		ser_yaml_indent(dt);
		apk_ostream_write_blob(dt->ser.os, APK_BLOB_STRLIT("-"));
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

static int ser_yaml_string(struct apk_serializer *ser, apk_blob_t scalar, int multiline)
{
	struct serialize_yaml *dt = container_of(ser, struct serialize_yaml, ser);
	apk_blob_t l, nl = APK_BLOB_STR("\n");

	ser_yaml_indent(dt);
	if (scalar.len >= 60 || multiline || need_quoting(scalar)) {
		/* long or multiline */
		apk_ostream_write_blob(dt->ser.os, APK_BLOB_STRLIT("|"));
		ser_yaml_newline(dt);
		dt->indent++;
		while (apk_blob_split(scalar, nl, &l, &scalar)) {
			ser_yaml_indent(dt);
			apk_ostream_write_blob(dt->ser.os, l);
			ser_yaml_newline(dt);
		}
		if (scalar.len) {
			ser_yaml_indent(dt);
			apk_ostream_write_blob(dt->ser.os, scalar);
			ser_yaml_newline(dt);
		}
		dt->indent--;
	} else {
		apk_ostream_write_blob(dt->ser.os, scalar);
		ser_yaml_newline(dt);
	}
	return 0;
}

static int ser_yaml_numeric(struct apk_serializer *ser, uint64_t val, int hint)
{
	struct serialize_yaml *dt = container_of(ser, struct serialize_yaml, ser);

	ser_yaml_indent(dt);
	apk_ostream_fmt(dt->ser.os, hint ? "%#llo" : "%llu", val);
	ser_yaml_newline(dt);
	return 0;
}

const struct apk_serializer_ops apk_serializer_yaml = {
	.context_size = sizeof(struct serialize_yaml),
	.start_schema = ser_yaml_start_schema,
	.start_array = ser_yaml_start_array,
	.start_object = ser_yaml_start_object,
	.end = ser_yaml_end,
	.comment = ser_yaml_comment,
	.key = ser_yaml_key,
	.string = ser_yaml_string,
	.numeric = ser_yaml_numeric,
};
