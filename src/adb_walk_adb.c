#include "adb.h"

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include "apk_adb.h"
#include "apk_applet.h"
#include "apk_print.h"

struct adb_walk_ctx {
	struct adb_walk *d;
	struct apk_trust *trust;
	struct adb db;
	struct adb_verify_ctx vfy;
};

static int adb_walk_block(struct adb *db, struct adb_block *b, struct apk_istream *is);
static int dump_object(struct adb_walk_ctx *ctx, const struct adb_object_schema *schema, adb_val_t v);

static int dump_item(struct adb_walk_ctx *ctx, const char *name, const uint8_t *kind, adb_val_t v)
{
	struct adb_walk *d = ctx->d;
	struct adb origdb;
	struct adb_obj o;
	struct adb_object_schema *obj_schema;
	struct apk_istream is;
	char tmp[256];
	apk_blob_t b;

	if (v == ADB_VAL_NULL) return 0;

	d->ops->key(d, name ? APK_BLOB_STR(name) : APK_BLOB_NULL);

	switch (*kind) {
	case ADB_KIND_ARRAY:
		obj_schema = container_of(kind, struct adb_object_schema, kind);
		adb_r_obj(&ctx->db, v, &o, obj_schema);
		//if (!adb_ra_num(&o)) return 0;

		d->ops->start_array(d, adb_ra_num(&o));
		for (size_t i = ADBI_FIRST; i <= adb_ra_num(&o); i++) {
			dump_item(ctx, NULL, obj_schema->fields[0].kind, adb_ro_val(&o, i));
		}
		d->ops->end(d);
		break;
	case ADB_KIND_ADB:
		apk_istream_from_blob(&is, adb_r_blob(&ctx->db, v));
		origdb = ctx->db;
		d->ops->start_object(d);
		adb_m_process(&ctx->db, &is,
			container_of(kind, struct adb_adb_schema, kind)->schema_id | ADB_SCHEMA_IMPLIED,
			0, NULL, adb_walk_block);
		d->ops->end(d);
		ctx->db = origdb;
		break;
	case ADB_KIND_OBJECT:;
		struct adb_object_schema *object = container_of(kind, struct adb_object_schema, kind);
		if (!object->tostring) {
			d->ops->start_object(d);
			dump_object(ctx, object, v);
			d->ops->end(d);
		} else {
			dump_object(ctx, object, v);
		}
		break;
	case ADB_KIND_BLOB:
	case ADB_KIND_INT:;
		struct adb_scalar_schema *scalar = container_of(kind, struct adb_scalar_schema, kind);
		if (scalar->tostring) {
			b = scalar->tostring(&ctx->db, v, tmp, sizeof tmp);
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

	adb_r_obj(&ctx->db, v, &o, schema);
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

static int adb_walk_block(struct adb *db, struct adb_block *b, struct apk_istream *is)
{
	struct adb_walk_ctx *ctx = container_of(db, struct adb_walk_ctx, db);
	struct adb_walk *d = ctx->d;
	char tmp[160];
	struct adb_hdr *hdr;
	struct adb_sign_hdr *s;
	uint32_t schema_magic = ctx->db.schema;
	const struct adb_db_schema *ds;
	uint64_t sz = adb_block_length(b);
	apk_blob_t data, c = APK_BLOB_BUF(tmp);
	int r;

	switch (adb_block_type(b)) {
	case ADB_BLOCK_ADB:
		d->ops->schema(d, db->schema);
		for (ds = d->schemas; ds->magic; ds++)
			if (ds->magic == schema_magic) break;
		hdr = apk_istream_peek(is, sizeof *hdr);
		if (IS_ERR(hdr)) return PTR_ERR(hdr);
		apk_blob_push_fmt(&c, "ADB block, size: %" PRIu64 ", compat: %d, ver: %d",
			sz, hdr->adb_compat_ver, hdr->adb_ver);
		d->ops->comment(d, apk_blob_pushed(APK_BLOB_BUF(tmp), c));
		if (ds->root && hdr->adb_compat_ver == 0) dump_object(ctx, ds->root, adb_r_root(db));
		return 0;
	case ADB_BLOCK_SIG:
		s = (struct adb_sign_hdr*) apk_istream_get(is, sz);
		data = APK_BLOB_PTR_LEN((char*)s, sz);
		r = adb_trust_verify_signature(ctx->trust, db, &ctx->vfy, data);
		apk_blob_push_fmt(&c, "sig v%02x h%02x ", s->sign_ver, s->hash_alg);
		for (size_t j = sizeof *s; j < data.len && c.len > 40; j++)
			apk_blob_push_fmt(&c, "%02x", (uint8_t)data.ptr[j]);
		if (c.len <= 40) apk_blob_push_blob(&c, APK_BLOB_STRLIT(".."));
		apk_blob_push_fmt(&c, ": %s", r ? apk_error_str(r) : "OK");
		break;
	case ADB_BLOCK_DATA:
		apk_blob_push_fmt(&c, "data block, size: %" PRIu64, sz);
		break;
	default:
		apk_blob_push_fmt(&c, "unknown block %d, size: %" PRIu64, adb_block_type(b), sz);
		break;
	}
	d->ops->comment(d, apk_blob_pushed(APK_BLOB_BUF(tmp), c));
	return 0;
}

int adb_walk_adb(struct adb_walk *d, struct apk_istream *is, struct apk_trust *trust)
{
	struct apk_trust allow_untrusted = {
		.allow_untrusted = 1,
	};
	struct adb_walk_ctx ctx = {
		.d = d,
		.trust = trust,
	};
	int r;

	if (IS_ERR(is)) return PTR_ERR(is);

	r = adb_m_process(&ctx.db, is, 0, &allow_untrusted, NULL, adb_walk_block);
	adb_free(&ctx.db);
	return r;
}
