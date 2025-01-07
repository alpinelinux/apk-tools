#include <stdio.h>
#include <unistd.h>
#include "apk_adb.h"
#include "apk_applet.h"
#include "apk_print.h"

static const struct adb_db_schema dbschemas[] = {
	{ .magic = ADB_SCHEMA_INDEX,		.root = &schema_index, },
	{ .magic = ADB_SCHEMA_INSTALLED_DB,	.root = &schema_idb, },
	{ .magic = ADB_SCHEMA_PACKAGE,		.root = &schema_package },
	{},
};

static int adbdump_main(void *pctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	struct apk_out *out = &ac->out;
	char **arg;
	int r;

	foreach_array_item(arg, args) {
		struct adb_walk walk = {
			.ops = &adb_walk_gentext_ops,
			.schemas = dbschemas,
			.trust = apk_ctx_get_trust(ac),
			.os = apk_ostream_to_fd(STDOUT_FILENO),
		};
		r = adb_walk_adb(&walk, adb_decompress(apk_istream_from_file_mmap(AT_FDCWD, *arg), NULL));
		if (r) {
			apk_err(out, "%s: %s", *arg, apk_error_str(r));
			return r;
		}
	}

	return 0;
}

static struct apk_applet apk_adbdump = {
	.name = "adbdump",
	.main = adbdump_main,
};
APK_DEFINE_APPLET(apk_adbdump);


static int adbgen_main(void *pctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	struct apk_out *out = &ac->out;
	char **arg;

	foreach_array_item(arg, args) {
		struct adb_walk walk = {
			.ops = &adb_walk_genadb_ops,
			.schemas = dbschemas,
			.trust = apk_ctx_get_trust(ac),
			.os = apk_ostream_to_fd(STDOUT_FILENO),
		};
		int r = adb_walk_text(&walk, apk_istream_from_file(AT_FDCWD, *arg));
		if (r) {
			apk_err(out, "%s: %s", *arg, apk_error_str(r));
			return r;
		}
	}

	return 0;
}

static struct apk_applet apk_adbgen = {
	.name = "adbgen",
	.main = adbgen_main,
};
APK_DEFINE_APPLET(apk_adbgen);

