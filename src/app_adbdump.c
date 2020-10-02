#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include "apk_adb.h"
#include "apk_applet.h"
#include "apk_print.h"

struct adb_dump_ctx {
	struct adb *db;
	struct adb_trust *trust;
	char prefix[128], *pfx;
};

struct adb_db_schema {
	unsigned long magic;
	const struct adb_object_schema *root;
};

static void ctx_nest(struct adb_dump_ctx *ctx, unsigned depth)
{
	while (depth--) *ctx->pfx++ = ' ';
	assert(ctx->pfx < &ctx->prefix[ARRAY_SIZE(ctx->prefix)]);
	*ctx->pfx = 0;
}

static void ctx_unnest(struct adb_dump_ctx *ctx, unsigned depth)
{
	ctx->pfx -= depth;
	assert(ctx->pfx >= ctx->prefix);
	*ctx->pfx = 0;
}

static void ctx_itemstart(struct adb_dump_ctx *ctx)
{
	ctx->pfx[-2] = '-';
}

static void ctx_itemdone(struct adb_dump_ctx *ctx)
{
	memset(ctx->prefix, ' ', ctx->pfx - ctx->prefix);
}

static void dump_object(struct adb_dump_ctx *ctx, const struct adb_object_schema *schema, adb_val_t v);
static void dump_adb(struct adb_dump_ctx *ctx);

static void dump_item(struct adb_dump_ctx *ctx, const char *name, const uint8_t *kind, adb_val_t v)
{
	struct adb db, *origdb;
	struct adb_obj o;
	struct adb_object_schema *obj_schema;
	char tmp[256];
	apk_blob_t b, nl = APK_BLOB_STR("\n");

	switch (*kind) {
	case ADB_KIND_ARRAY:
		obj_schema = container_of(kind, struct adb_object_schema, kind);
		adb_r_obj(ctx->db, v, &o, obj_schema);
		if (!adb_ra_num(&o)) return;

		fprintf(stdout, "%s%s: # %u items\n", ctx->prefix, name, adb_ra_num(&o));
		ctx_nest(ctx, 4);
		for (size_t i = ADBI_FIRST; i <= adb_ra_num(&o); i++) {
			ctx_itemstart(ctx);
			dump_item(ctx, NULL, obj_schema->fields[0].kind, adb_ro_val(&o, i));
			ctx_itemdone(ctx);
		}
		ctx_unnest(ctx, 4);
		break;
	case ADB_KIND_ADB:
		db.hdr.schema = container_of(kind, struct adb_adb_schema, kind)->schema_id;
		db.data = adb_r_blob(ctx->db, v);
		origdb = ctx->db;
		ctx->db = &db;
		dump_adb(ctx);
		ctx->db = origdb;
		break;
	case ADB_KIND_OBJECT:
		if (name) {
			fprintf(stdout, "%s%s:\n", ctx->prefix, name);
			ctx_nest(ctx, 4);
		}
		dump_object(ctx, container_of(kind, struct adb_object_schema, kind), v);
		if (name) ctx_unnest(ctx, 4);
		break;
	case ADB_KIND_BLOB:
	case ADB_KIND_INT:;
		struct adb_scalar_schema *scalar = container_of(kind, struct adb_scalar_schema, kind);
		if (scalar->tostring) {
			b = scalar->tostring(ctx->db, v, tmp, sizeof tmp);
		} else {
			b = APK_BLOB_STR("(unknown)");
		}
		if (!APK_BLOB_IS_NULL(b)) {
			fputs(ctx->prefix, stdout);
			if (name) fprintf(stdout, "%s: ", name);
			if (b.len >= 60 || scalar->multiline) {
				/* long or multiline */
				apk_blob_t l;
				fprintf(stdout, "|\n");
				ctx_itemdone(ctx);
				ctx_nest(ctx, 4);
				while (apk_blob_split(b, nl, &l, &b)) {
					fprintf(stdout, "%s"BLOB_FMT"\n",
						ctx->prefix, BLOB_PRINTF(l));
				}
				if (b.len) {
					fprintf(stdout, "%s"BLOB_FMT"\n",
						ctx->prefix, BLOB_PRINTF(b));
				}
				ctx_unnest(ctx, 4);
			} else {
				fwrite(b.ptr, 1, b.len, stdout);
				fputc('\n', stdout);
			}
		}
		break;
	}
}

static void dump_object(struct adb_dump_ctx *ctx, const struct adb_object_schema *schema, adb_val_t v)
{
	size_t schema_len = 0;
	struct adb_obj o;
	char tmp[256];
	apk_blob_t b;

	adb_r_obj(ctx->db, v, &o, schema);
	if (schema) {
		if (schema->tostring) {
			b = schema->tostring(&o, tmp, sizeof tmp);
			if (!APK_BLOB_IS_NULL(b))
				fprintf(stdout, "%s"BLOB_FMT"\n", ctx->prefix, BLOB_PRINTF(b));
			ctx_itemdone(ctx);
			return;
		}
		schema_len = schema->num_fields;
	}

	for (size_t i = ADBI_FIRST; i < adb_ro_num(&o); i++) {
		adb_val_t val = adb_ro_val(&o, i);
		if (val == ADB_NULL) continue;
		if (i < schema_len && schema->fields[i-1].kind != 0) {
			dump_item(ctx, schema->fields[i-1].name, schema->fields[i-1].kind, val);
			ctx_itemdone(ctx);
		}
	}
}

static const struct adb_db_schema dbschemas[] = {
	{ .magic = ADB_SCHEMA_INDEX,		.root = &schema_index, },
	{ .magic = ADB_SCHEMA_INSTALLED_DB,	.root = &schema_idb, },
	{ .magic = ADB_SCHEMA_PACKAGE,		.root = &schema_package },
};

static void dump_adb(struct adb_dump_ctx *ctx)
{
	struct adb_block *blk;
	struct adb_sign_hdr *s;
	struct adb_verify_ctx vfy = {};
	const struct adb_db_schema *ds;
	unsigned char *id;
	uint32_t schema_magic = ctx->db->hdr.schema;
	int r;

	for (ds = dbschemas; ds < &dbschemas[ARRAY_SIZE(dbschemas)]; ds++)
		if (ds->magic == schema_magic) break;
	if (ds >= &dbschemas[ARRAY_SIZE(dbschemas)]) ds = NULL;

	adb_foreach_block(blk, ctx->db->data) {
		apk_blob_t b = APK_BLOB_PTR_LEN((char*)(blk+1), ADB_BLOCK_SIZE(blk));
		switch (ADB_BLOCK_TYPE(blk)) {
		case ADB_BLOCK_ADB:
			fprintf(stdout, "%s# ADB block, size: %d\n", ctx->prefix, ADB_BLOCK_SIZE(blk));
			ctx_itemdone(ctx);
			ctx->db->adb = b;
			if (ds)
				dump_object(ctx, ds->root, adb_r_root(ctx->db));
			else
				fprintf(stdout, "%s# Unrecognized schema: 0x%08x\n", ctx->prefix, schema_magic);
			break;
		case ADB_BLOCK_SIG:
			s = (struct adb_sign_hdr*) b.ptr;
			fprintf(stdout, "%s# signature: v%d ", ctx->prefix, s->sign_ver);
			ctx_itemdone(ctx);
			r = adb_trust_verify_signature(ctx->trust, ctx->db, &vfy, b);
			switch (s->sign_ver) {
			case 0:
				id = (unsigned char*)(s + 1);
				for (size_t j = 0; j < 16; j++)
					fprintf(stdout, "%02x", id[j]);
				break;
			default:
				break;
			}
			fprintf(stdout, ": %s\n", r ? apk_error_str(r) : "OK");
			break;
		default:
			fprintf(stdout, "%s# unknown block %d, size: %d\n",
				ctx->prefix, ADB_BLOCK_TYPE(blk), ADB_BLOCK_SIZE(blk));
			ctx_itemdone(ctx);
		}
	}
	if (IS_ERR(blk)) fprintf(stdout, "%s# block enumeration error: corrupt data area\n", ctx->prefix);
}

static int mmap_and_dump_adb(struct adb_trust *trust, int fd)
{
	struct adb db;
	struct adb_dump_ctx ctx = {
		.db = &db,
		.pfx = ctx.prefix,
		.trust = trust,
	};
	int r;

	r = adb_m_map(&db, fd, 0, NULL);
	if (r) return r;

	dump_adb(&ctx);
	adb_free(&db);
	return 0;
}

static int adbdump_main(void *pctx, struct apk_database *db, struct apk_string_array *args)
{
	char **arg;
	int r;

	foreach_array_item(arg, args) {
		r = mmap_and_dump_adb(&db->trust, open(*arg, O_RDONLY));
		if (r) {
			apk_error("%s: %s", *arg, apk_error_str(r));
			return r;
		}
	}

	return 0;
}

static struct apk_applet apk_adbdump = {
	.name = "adbdump",
	.open_flags = APK_OPENF_READ | APK_OPENF_NO_STATE | APK_OPENF_NO_REPOS,
	.main = adbdump_main,
};
APK_DEFINE_APPLET(apk_adbdump);

