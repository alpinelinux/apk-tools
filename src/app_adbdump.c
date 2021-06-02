#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include "apk_adb.h"
#include "apk_applet.h"
#include "apk_print.h"

static const struct adb_db_schema dbschemas[] = {
	{ .magic = ADB_SCHEMA_INDEX,		.root = &schema_index, },
	{ .magic = ADB_SCHEMA_INSTALLED_DB,	.root = &schema_idb, },
	{ .magic = ADB_SCHEMA_PACKAGE,		.root = &schema_package },
	{},
};

static int mmap_and_dump_adb(struct apk_trust *trust, int fd, struct apk_out *out)
{
	struct adb db;
	struct adb_walk_gentext td = {
		.d.ops = &adb_walk_gentext_ops,
		.d.schemas = dbschemas,
		.out = out->out,
	};
	int r;

	r = adb_m_map(&db, fd, 0, NULL);
	if (r) return r;

	adb_walk_adb(&td.d, &db, trust);
	adb_free(&db);
	return 0;
}

static int adbdump_main(void *pctx, struct apk_ctx *ac, struct apk_string_array *args)
{
	struct apk_out *out = &ac->out;
	char **arg;
	int r;

	foreach_array_item(arg, args) {
		r = mmap_and_dump_adb(apk_ctx_get_trust(ac), open(*arg, O_RDONLY), out);
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
	int r;
	struct adb_walk_genadb genadb = {
		.d.ops = &adb_walk_genadb_ops,
		.d.schemas = dbschemas,
	};

	adb_w_init_alloca(&genadb.db, 0, 1000);
	adb_w_init_alloca(&genadb.idb[0], 0, 100);
	foreach_array_item(arg, args) {
		adb_reset(&genadb.db);
		r = adb_walk_istream(&genadb.d, apk_istream_from_file(AT_FDCWD, *arg));
		if (!r) {
			r = adb_c_create(apk_ostream_to_fd(STDOUT_FILENO), &genadb.db,
				apk_ctx_get_trust(ac));
		}
		adb_free(&genadb.db);
		adb_free(&genadb.idb[0]);
		if (r) apk_err(out, "%s: %s", *arg, apk_error_str(r));
	}

	return 0;
}

static struct apk_applet apk_adbgen = {
	.name = "adbgen",
	.main = adbgen_main,
};
APK_DEFINE_APPLET(apk_adbgen);

