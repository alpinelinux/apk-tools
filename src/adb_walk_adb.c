#include "adb.h"

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include "apk_adb.h"
#include "apk_applet.h"
#include "apk_print.h"

struct adb_walk_ctx {
	struct adb_walk *d;
	struct adb *db;
	struct apk_trust *trust;
};

static int dump_object(struct adb_walk_ctx *ctx, const struct adb_object_schema *schema, adb_val_t v);
static int dump_adb(struct adb_walk_ctx *ctx);

static int dump_item(struct adb_walk_ctx *ctx, const char *name, const uint8_t *kind, adb_val_t v)
{
	struct adb_walk *d = ctx->d;
	struct adb db, *origdb;
	struct adb_obj o;
	struct adb_object_schema *obj_schema;
	char tmp[256];
	apk_blob_t b;

	if (v == ADB_VAL_NULL) return 0;

	d->ops->key(d, name ? APK_BLOB_STR(name) : APK_BLOB_NULL);

	switch (*kind) {
	case ADB_KIND_ARRAY:
		obj_schema = container_of(kind, struct adb_object_schema, kind);
		adb_r_obj(ctx->db, v, &o, obj_schema);
		//if (!adb_ra_num(&o)) return 0;

		d->ops->start_array(d, adb_ra_num(&o));
		for (size_t i = ADBI_FIRST; i <= adb_ra_num(&o); i++) {
			dump_item(ctx, NULL, obj_schema->fields[0].kind, adb_ro_val(&o, i));
		}
		d->ops->end(d);
		break;
	case ADB_KIND_ADB:
		db.hdr.schema = container_of(kind, struct adb_adb_schema, kind)->schema_id;
		db.data = adb_r_blob(ctx->db, v);
		origdb = ctx->db;
		ctx->db = &db;
		d->ops->start_object(d);
		dump_adb(ctx);
		d->ops->end(d);
		ctx->db = origdb;
		break;
	case ADB_KIND_OBJECT:
		d->ops->start_object(d);
		dump_object(ctx, container_of(kind, struct adb_object_schema, kind), v);
		d->ops->end(d);
		break;
	case ADB_KIND_BLOB:
	case ADB_KIND_INT:;
		struct adb_scalar_schema *scalar = container_of(kind, struct adb_scalar_schema, kind);
		if (scalar->tostring) {
			b = scalar->tostring(ctx->db, v, tmp, sizeof tmp);
		} else {
			b = APK_BLOB_STR("(unknown)");
		}
		if (!APK_BLOB_IS_NULL(b))
			d->ops->scalar(d, b, scalar->multiline);
		break;
	}
	return 0;
}

static int dump_object(struct adb_walk_ctx *ctx, const struct adb_object_schema *schema, adb_val_t v)
{
	size_t schema_len = 0;
	struct adb_obj o;
	char tmp[256];
	apk_blob_t b;
	struct adb_walk *d = ctx->d;

	adb_r_obj(ctx->db, v, &o, schema);
	if (schema) {
		if (schema->tostring) {
			b = schema->tostring(&o, tmp, sizeof tmp);
			if (!APK_BLOB_IS_NULL(b))
				d->ops->scalar(d, b, 0);
			return 0;
		}
		schema_len = schema->num_fields;
	}

	for (size_t i = ADBI_FIRST; i < adb_ro_num(&o); i++) {
		adb_val_t val = adb_ro_val(&o, i);
		if (val == ADB_NULL) continue;
		if (i < schema_len && schema->fields[i-1].kind != 0) {
			dump_item(ctx, schema->fields[i-1].name, schema->fields[i-1].kind, val);
		}
	}
	return 0;
}

static int dump_adb(struct adb_walk_ctx *ctx)
{
	char tmp[256];
	struct adb_block *blk;
	struct adb_sign_hdr *s;
	struct adb_verify_ctx vfy = {};
	unsigned char *id;
	uint32_t schema_magic = ctx->db->hdr.schema;
	const struct adb_db_schema *ds;
	struct adb_walk *d = ctx->d;
	int r, len;

	for (ds = d->schemas; ds->magic; ds++)
		if (ds->magic == schema_magic) break;

	adb_foreach_block(blk, ctx->db->data) {
		apk_blob_t b = APK_BLOB_PTR_LEN((char*)(blk+1), ADB_BLOCK_SIZE(blk));
		switch (ADB_BLOCK_TYPE(blk)) {
		case ADB_BLOCK_ADB:
			len = snprintf(tmp, sizeof tmp, "ADB block, size: %u", ADB_BLOCK_SIZE(blk));
			d->ops->comment(d, APK_BLOB_PTR_LEN(tmp, len));
			if (ds->root) {
				ctx->db->adb = b;
				dump_object(ctx, ds->root, adb_r_root(ctx->db));
			}
			break;
		case ADB_BLOCK_SIG:
			s = (struct adb_sign_hdr*) b.ptr;
			r = adb_trust_verify_signature(ctx->trust, ctx->db, &vfy, b);

			len = snprintf(tmp, sizeof tmp, "signature: v%d ", s->sign_ver);
			switch (s->sign_ver) {
			case 0:
				id = (unsigned char*)(s + 1);
				for (size_t j = 0; j < 16; j++)
					len += snprintf(&tmp[len], sizeof tmp - len, "%02x", id[j]);
				break;
			default:
				break;
			}
			len += snprintf(&tmp[len], sizeof tmp - len, ": %s", r ? apk_error_str(r) : "OK");
			d->ops->comment(d, APK_BLOB_PTR_LEN(tmp, len));
			break;
		default:
			len = snprintf(tmp, sizeof tmp, "unknown block %d, size: %d",
				ADB_BLOCK_TYPE(blk), ADB_BLOCK_SIZE(blk));
			d->ops->comment(d, APK_BLOB_PTR_LEN(tmp, len));
		}
	}
	if (IS_ERR(blk)) {
		d->ops->comment(d, APK_BLOB_STRLIT("block enumeration error: corrupt data area"));
	}
	return 0;
}

int adb_walk_adb(struct adb_walk *d, struct adb *db, struct apk_trust *trust)
{
	struct adb_walk_ctx ctx = {
		.d = d,
		.db = db,
		.trust = trust,
	};
	return dump_adb(&ctx);
}
