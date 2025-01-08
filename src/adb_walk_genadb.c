#include <errno.h>
#include "adb.h"
#include "apk_print.h"

#define ADB_WALK_GENADB_MAX_IDB		2
#define ADB_WALK_GENADB_MAX_VALUES	100000

struct adb_walk_genadb {
	struct adb db;
	struct adb idb[ADB_WALK_GENADB_MAX_IDB];
	int nest, nestdb, num_vals;
	struct adb_obj objs[ADB_WALK_MAX_NESTING];
	unsigned int curkey[ADB_WALK_MAX_NESTING];
	adb_val_t vals[ADB_WALK_GENADB_MAX_VALUES];

	struct list_head db_buckets[1000];
	struct list_head idb_buckets[100];
};

static struct adb_walk_genadb *walk_genadb_ctx(struct adb_walk *walk)
{
	return (struct adb_walk_genadb *) walk->ctx[0];
}

static int adb_walk_genadb_init(struct adb_walk *d)
{
	struct adb_walk_genadb *dt;

	dt = calloc(1, sizeof *dt);
	if (!dt) return -ENOMEM;
	d->ctx[0] = (unsigned long) dt;
	adb_w_init_dynamic(&dt->db, 0, dt->db_buckets, ARRAY_SIZE(dt->db_buckets));
	adb_w_init_dynamic(&dt->idb[0], 0, dt->idb_buckets, ARRAY_SIZE(dt->idb_buckets));
	return 0;
}

static void adb_walk_genadb_cleanup(struct adb_walk *d)
{
	struct adb_walk_genadb *dt = walk_genadb_ctx(d);

	adb_free(&dt->db);
	adb_free(&dt->idb[0]);
	free((void*) d->ctx[0]);
	d->ctx[0] = 0;
}

static int adb_walk_genadb_start_schema(struct adb_walk *d, uint32_t schema_id)
{
	struct adb_walk_genadb *dt = walk_genadb_ctx(d);
	const struct adb_db_schema *s;

	dt->db.schema = schema_id;
	for (s = d->schemas; s->magic; s++)
		if (s->magic == schema_id) break;
	if (!s || !s->magic) return -APKE_ADB_SCHEMA;

	adb_wo_init(&dt->objs[0], &dt->vals[0], s->root, &dt->db);
	dt->num_vals += s->root->num_fields;
	if (dt->num_vals >= ARRAY_SIZE(dt->vals)) return -APKE_ADB_LIMIT;
	dt->nest = 0;

	return 0;
}

static int adb_walk_genadb_start_object(struct adb_walk *d)
{
	struct adb_walk_genadb *dt = walk_genadb_ctx(d);

	if (!dt->db.schema) return -APKE_ADB_SCHEMA;
	if (dt->nest >= ARRAY_SIZE(dt->objs)) return -APKE_ADB_LIMIT;

	if (dt->curkey[dt->nest] == 0 &&
	    dt->objs[dt->nest].schema->kind == ADB_KIND_OBJECT)
		return -APKE_ADB_SCHEMA;

	dt->nest++;
	adb_wo_init_val(
		&dt->objs[dt->nest], &dt->vals[dt->num_vals],
		&dt->objs[dt->nest-1], dt->curkey[dt->nest-1]);

	if (*adb_ro_kind(&dt->objs[dt->nest-1], dt->curkey[dt->nest-1]) == ADB_KIND_ADB) {
		struct adb_adb_schema *schema = container_of(&dt->objs[dt->nest-1].schema->kind, struct adb_adb_schema, kind);
		if (dt->nestdb >= ARRAY_SIZE(dt->idb)) return -APKE_ADB_LIMIT;
		adb_reset(&dt->idb[dt->nestdb]);
		dt->idb[dt->nestdb].schema = schema->schema_id;
		dt->objs[dt->nest].db = &dt->idb[dt->nestdb];
		dt->nestdb++;
	}

	dt->num_vals += dt->objs[dt->nest].schema->num_fields;
	if (dt->num_vals >= ARRAY_SIZE(dt->vals)) return -APKE_ADB_LIMIT;

	return 0;
}

static int adb_walk_genadb_start_array(struct adb_walk *d, unsigned int num)
{
	return adb_walk_genadb_start_object(d);
}

static int adb_walk_genadb_end(struct adb_walk *d)
{
	struct adb_walk_genadb *dt = walk_genadb_ctx(d);
	adb_val_t val;

	val = adb_w_obj(&dt->objs[dt->nest]);
	if (ADB_IS_ERROR(val))
		return -ADB_VAL_VALUE(val);

	dt->curkey[dt->nest] = 0;
	dt->num_vals -= dt->objs[dt->nest].schema->num_fields;

	if (dt->nest == 0) {
		adb_w_root(&dt->db, val);
		int r = adb_c_create(d->os, &dt->db, d->trust);
		d->os = NULL;
		return r;
	}

	dt->nest--;

	if (*adb_ro_kind(&dt->objs[dt->nest], dt->curkey[dt->nest]) == ADB_KIND_ADB) {
		dt->nestdb--;
		adb_w_root(&dt->idb[dt->nestdb], val);
		val = adb_w_adb(&dt->db, &dt->idb[dt->nestdb]);
	}

	if (dt->curkey[dt->nest] == 0) {
		adb_wa_append(&dt->objs[dt->nest], val);
	} else {
		adb_wo_val(&dt->objs[dt->nest], dt->curkey[dt->nest], val);
		dt->curkey[dt->nest] = 0;
	}

	return 0;
}

static int adb_walk_genadb_comment(struct adb_walk *d, apk_blob_t comment)
{
	return 0;
}

static int adb_walk_genadb_key(struct adb_walk *d, apk_blob_t key)
{
	struct adb_walk_genadb *dt = walk_genadb_ctx(d);
	uint8_t kind = dt->objs[dt->nest].schema->kind;

	if (kind != ADB_KIND_OBJECT && kind != ADB_KIND_ADB)
		return -APKE_ADB_SCHEMA;

	dt->curkey[dt->nest] = adb_s_field_by_name_blob(dt->objs[dt->nest].schema, key);
	if (dt->curkey[dt->nest] == 0)
		return -APKE_ADB_SCHEMA;

	return 0;
}

static int adb_walk_genadb_scalar(struct adb_walk *d, apk_blob_t scalar, int multiline)
{
	struct adb_walk_genadb *dt = walk_genadb_ctx(d);

	if (dt->objs[dt->nest].schema->kind == ADB_KIND_ARRAY) {
		adb_wa_append_fromstring(&dt->objs[dt->nest], scalar);
	} else {
		if (dt->curkey[dt->nest] == 0)
			adb_wo_fromstring(&dt->objs[dt->nest], scalar);
		else
			adb_wo_val_fromstring(&dt->objs[dt->nest], dt->curkey[dt->nest], scalar);
	}
	dt->curkey[dt->nest] = 0;

	return 0;
}

const struct adb_walk_ops adb_walk_genadb_ops = {
	.init = adb_walk_genadb_init,
	.cleanup = adb_walk_genadb_cleanup,
	.start_schema = adb_walk_genadb_start_schema,
	.start_array = adb_walk_genadb_start_array,
	.start_object = adb_walk_genadb_start_object,
	.end = adb_walk_genadb_end,
	.comment = adb_walk_genadb_comment,
	.key = adb_walk_genadb_key,
	.scalar = adb_walk_genadb_scalar,
};
