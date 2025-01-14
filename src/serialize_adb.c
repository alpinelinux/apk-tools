#include <errno.h>
#include "adb.h"
#include "apk_print.h"

#define SERIALIZE_ADB_MAX_IDB		2
#define SERIALIZE_ADB_MAX_VALUES	100000

struct serialize_adb {
	struct apk_serializer ser;

	struct adb db;
	struct adb idb[SERIALIZE_ADB_MAX_IDB];
	int nest, nestdb, num_vals;
	struct adb_obj objs[APK_SERIALIZE_MAX_NESTING];
	unsigned int curkey[APK_SERIALIZE_MAX_NESTING];
	adb_val_t vals[SERIALIZE_ADB_MAX_VALUES];

	struct list_head db_buckets[1000];
	struct list_head idb_buckets[100];
};

static int ser_adb_init(struct apk_serializer *ser)
{
	struct serialize_adb *dt = container_of(ser, struct serialize_adb, ser);

	adb_w_init_dynamic(&dt->db, 0, dt->db_buckets, ARRAY_SIZE(dt->db_buckets));
	adb_w_init_dynamic(&dt->idb[0], 0, dt->idb_buckets, ARRAY_SIZE(dt->idb_buckets));
	return 0;
}

static void ser_adb_cleanup(struct apk_serializer *ser)
{
	struct serialize_adb *dt = container_of(ser, struct serialize_adb, ser);

	adb_free(&dt->db);
	adb_free(&dt->idb[0]);
}

static int ser_adb_start_object(struct apk_serializer *ser, uint32_t schema_id)
{
	struct serialize_adb *dt = container_of(ser, struct serialize_adb, ser);

	if (dt->db.schema == 0) {
		const struct adb_db_schema *s;
		dt->db.schema = schema_id;
		for (s = adb_all_schemas; s->magic; s++)
			if (s->magic == schema_id) break;
		if (!s || !s->magic) return -APKE_ADB_SCHEMA;

		adb_wo_init(&dt->objs[0], &dt->vals[0], s->root, &dt->db);
		dt->num_vals += s->root->num_fields;
	} else {
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
	}
	if (dt->num_vals >= ARRAY_SIZE(dt->vals)) return -APKE_ADB_LIMIT;
	return 0;
}

static int ser_adb_start_array(struct apk_serializer *ser, unsigned int num)
{
	return ser_adb_start_object(ser, 0);
}

static int ser_adb_end(struct apk_serializer *ser)
{
	struct serialize_adb *dt = container_of(ser, struct serialize_adb, ser);
	adb_val_t val;

	val = adb_w_obj(&dt->objs[dt->nest]);
	adb_wo_free(&dt->objs[dt->nest]);
	if (ADB_IS_ERROR(val))
		return -ADB_VAL_VALUE(val);

	dt->curkey[dt->nest] = 0;
	dt->num_vals -= dt->objs[dt->nest].schema->num_fields;

	if (dt->nest == 0) {
		adb_w_root(&dt->db, val);
		int r = adb_c_create(dt->ser.os, &dt->db, dt->ser.trust);
		dt->ser.os = NULL;
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

static int ser_adb_comment(struct apk_serializer *ser, apk_blob_t comment)
{
	return 0;
}

static int ser_adb_key(struct apk_serializer *ser, apk_blob_t key)
{
	struct serialize_adb *dt = container_of(ser, struct serialize_adb, ser);
	uint8_t kind = dt->objs[dt->nest].schema->kind;

	if (kind != ADB_KIND_OBJECT && kind != ADB_KIND_ADB)
		return -APKE_ADB_SCHEMA;

	dt->curkey[dt->nest] = adb_s_field_by_name_blob(dt->objs[dt->nest].schema, key);
	if (dt->curkey[dt->nest] == 0)
		return -APKE_ADB_SCHEMA;

	return 0;
}

static int ser_adb_string(struct apk_serializer *ser, apk_blob_t scalar, int multiline)
{
	struct serialize_adb *dt = container_of(ser, struct serialize_adb, ser);

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

const struct apk_serializer_ops apk_serializer_adb = {
	.context_size = sizeof(struct serialize_adb),
	.init = ser_adb_init,
	.cleanup = ser_adb_cleanup,
	.start_object = ser_adb_start_object,
	.start_array = ser_adb_start_array,
	.end = ser_adb_end,
	.comment = ser_adb_comment,
	.key = ser_adb_key,
	.string = ser_adb_string,
};
