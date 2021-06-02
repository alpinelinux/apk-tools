#include "adb.h"
#include "apk_print.h"

static void adb_walk_gentext_indent(struct adb_walk_gentext *dt)
{
	int i;

	if (!dt->line_started) {
		for (i = 0; i < dt->nest; i++) {
			fprintf(dt->out, "  ");
		}
	} else {
		fprintf(dt->out, " ");
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
	struct adb_walk_gentext *dt = container_of(d, struct adb_walk_gentext, d);
	FILE *out = dt->out;

	adb_walk_gentext_indent(dt);
	fprintf(out, "#%%SCHEMA: %08X\n", schema_id);
	adb_walk_gentext_newline(dt);
	return 0;
}

static int adb_walk_gentext_comment(struct adb_walk *d, apk_blob_t comment)
{
	struct adb_walk_gentext *dt = container_of(d, struct adb_walk_gentext, d);
	FILE *out = dt->out;

	adb_walk_gentext_indent(dt);
	fprintf(out, "# "BLOB_FMT"\n", BLOB_PRINTF(comment));
	adb_walk_gentext_newline(dt);
	return 0;
}

static int adb_walk_gentext_start_array(struct adb_walk *d, unsigned int num)
{
	struct adb_walk_gentext *dt = container_of(d, struct adb_walk_gentext, d);
	FILE *out = dt->out;

	adb_walk_gentext_indent(dt);
	fprintf(out, "# %d items\n", num);
	adb_walk_gentext_newline(dt);
	dt->nest++;
	return 0;
}

static int adb_walk_gentext_start_object(struct adb_walk *d)
{
	struct adb_walk_gentext *dt = container_of(d, struct adb_walk_gentext, d);

	dt->nest++;
	return 0;
}

static int adb_walk_gentext_end(struct adb_walk *d)
{
	struct adb_walk_gentext *dt = container_of(d, struct adb_walk_gentext, d);
	FILE *out = dt->out;

	if (dt->line_started) {
		adb_walk_gentext_indent(dt);
		fprintf(out, "# empty object\n");
		adb_walk_gentext_newline(dt);
	}
	dt->nest--;
	return 0;
}

static int adb_walk_gentext_key(struct adb_walk *d, apk_blob_t key)
{
	struct adb_walk_gentext *dt = container_of(d, struct adb_walk_gentext, d);
	FILE *out = dt->out;

	if (!APK_BLOB_IS_NULL(key)) {
		if (dt->key_printed) {
			fprintf(out, "\n");
			adb_walk_gentext_newline(dt);
		}
		adb_walk_gentext_indent(dt);
		fprintf(out, BLOB_FMT":", BLOB_PRINTF(key));
		dt->key_printed = 1;
	} else {
		adb_walk_gentext_indent(dt);
		fprintf(out, "-");
	}
	return 0;
}

static int adb_walk_gentext_scalar(struct adb_walk *d, apk_blob_t scalar, int multiline)
{
	struct adb_walk_gentext *dt = container_of(d, struct adb_walk_gentext, d);
	FILE *out = dt->out;
	apk_blob_t nl = APK_BLOB_STR("\n");

	adb_walk_gentext_indent(dt);

	if (scalar.len >= 60 || multiline) {
		/* long or multiline */
		apk_blob_t l;

		fprintf(out, "|\n");
		adb_walk_gentext_newline(dt);

		dt->nest++;
		while (apk_blob_split(scalar, nl, &l, &scalar)) {
			adb_walk_gentext_indent(dt);
			fprintf(out, BLOB_FMT"\n", BLOB_PRINTF(l));
			adb_walk_gentext_newline(dt);
		}
		if (scalar.len) {
			adb_walk_gentext_indent(dt);
			fprintf(out, BLOB_FMT"\n", BLOB_PRINTF(scalar));
			adb_walk_gentext_newline(dt);
		}
		dt->nest--;
	} else {
		fprintf(out, BLOB_FMT"\n", BLOB_PRINTF(scalar));
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
