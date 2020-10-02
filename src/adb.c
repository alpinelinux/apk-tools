#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <assert.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "adb.h"
#include "apk_blob.h"

/* Block enumeration */
static inline struct adb_block *adb_block_validate(struct adb_block *blk, apk_blob_t b)
{
	size_t pos = (char *)blk - b.ptr;
	if (pos == b.len) return NULL;
	pos += sizeof(struct adb_block);
	if (pos > b.len || ADB_BLOCK_SIZE(blk) > b.len - pos) return ERR_PTR(-EBADMSG);
	return blk;
}

struct adb_block *adb_block_first(apk_blob_t b)
{
	return adb_block_validate((struct adb_block*)b.ptr, b);
}

struct adb_block *adb_block_next(struct adb_block *cur, apk_blob_t b)
{
	return adb_block_validate((struct adb_block*)((char*)cur + sizeof(struct adb_block) + ADB_BLOCK_SIZE(cur)), b);
}

/* Init stuff */
int adb_free(struct adb *db)
{
	if (db->mmap.ptr) {
		munmap(db->mmap.ptr, db->mmap.len);
	} else {
		struct adb_w_bucket *bucket, *nxt;
		int i;

		for (i = 0; i < db->num_buckets; i++)
			list_for_each_entry_safe(bucket, nxt, &db->bucket[i], node)
				free(bucket);
		free(db->adb.ptr);
	}
	return 0;
}

void adb_reset(struct adb *db)
{
	struct adb_w_bucket *bucket, *nxt;
	int i;

	for (i = 0; i < db->num_buckets; i++) {
		list_for_each_entry_safe(bucket, nxt, &db->bucket[i], node)
			free(bucket);
		list_init(&db->bucket[i]);
	}
	db->adb.len = 0;
}

static int __adb_m_parse(struct adb *db, struct adb_trust *t)
{
	struct adb_verify_ctx vfy = {};
	struct adb_block *blk;
	int r = -EBADMSG;
	int trusted = t ? 0 : 1;

	adb_foreach_block(blk, db->data) {
		apk_blob_t b = APK_BLOB_PTR_LEN((char*)(blk+1), ADB_BLOCK_SIZE(blk));
		switch (ADB_BLOCK_TYPE(blk)) {
		case ADB_BLOCK_ADB:
			if (!APK_BLOB_IS_NULL(db->adb)) break;
			db->adb = b;
			break;
		case ADB_BLOCK_SIG:
			if (APK_BLOB_IS_NULL(db->adb)) break;
			if (!trusted &&
			    adb_trust_verify_signature(t, db, &vfy, b) == 0)
				trusted = 1;
			break;
		default:
			if (APK_BLOB_IS_NULL(db->adb)) break;
			break;
		}
	}
	if (IS_ERR(blk)) r = PTR_ERR(blk);
	else if (!trusted) r = -ENOKEY;
	else if (db->adb.ptr) r = 0;

	if (r != 0) {
		db->adb = APK_BLOB_NULL;
	}
	return r;
}

int adb_m_blob(struct adb *db, apk_blob_t blob, struct adb_trust *t)
{
	*db = (struct adb) { .data = blob };
	return __adb_m_parse(db, t);
}

int adb_m_map(struct adb *db, int fd, uint32_t expected_schema, struct adb_trust *t)
{
	struct stat st;
	struct adb_header *hdr;
	int r = -EBADMSG;

	if (fstat(fd, &st) != 0) return -errno;
	if (st.st_size < sizeof *hdr) return -EIO;

	memset(db, 0, sizeof *db);
	db->mmap.ptr = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	db->mmap.len = st.st_size;
	if (db->mmap.ptr == MAP_FAILED) return -errno;

	hdr = (struct adb_header *) db->mmap.ptr;
	if (hdr->magic != htole32(ADB_FORMAT_MAGIC)) goto err;
	if (expected_schema && expected_schema != le32toh(hdr->schema)) goto err;

	db->hdr = *hdr;
	db->data = APK_BLOB_PTR_LEN(db->mmap.ptr + sizeof *hdr, db->mmap.len - sizeof *hdr);
	r = __adb_m_parse(db, t);
	if (r) goto err;
	return 0;
err:
	adb_free(db);
	return r;
}

int adb_w_init_dynamic(struct adb *db, uint32_t schema, void *buckets, size_t num_buckets)
{
	size_t i;

	*db = (struct adb) {
		.hdr.magic = htole32(ADB_FORMAT_MAGIC),
		.hdr.schema = htole32(schema),
		.num_buckets = num_buckets,
		.bucket = buckets,
	};

	if (num_buckets) {
		for (i = 0; i < db->num_buckets; i++)
			list_init(&db->bucket[i]);
	}

	return 0;
}

int adb_w_init_static(struct adb *db, void *buf, size_t bufsz)
{
	*db = (struct adb) {
		.hdr.magic = htole32(ADB_FORMAT_MAGIC),
		.adb.ptr = buf,
		.mmap.len = bufsz,
	};
	return 0;
}

/* Read interface */
static inline void *adb_r_deref(const struct adb *db, adb_val_t v, size_t offs, size_t s)
{
	offs += ADB_VAL_VALUE(v);
	if (offs + s > db->adb.len) return NULL;
	return db->adb.ptr + offs;
}

adb_val_t adb_r_root(const struct adb *db)
{
	if (db->adb.len < sizeof(adb_val_t)) return ADB_NULL;
	return *(adb_val_t *)(db->adb.ptr + db->adb.len - sizeof(adb_val_t));
}

uint32_t adb_r_int(const struct adb *db, adb_val_t v)
{
	uint32_t *int4;

	switch (ADB_VAL_TYPE(v)) {
	case ADB_TYPE_INT:
		return ADB_VAL_VALUE(v);
	case ADB_TYPE_INT_32:
		int4 = adb_r_deref(db, v, 0, sizeof int4);
		if (!int4) return 0;
		return le32toh(*int4);
	default:
		return 0;
	}
}

apk_blob_t adb_r_blob(const struct adb *db, adb_val_t v)
{
	void *blob;
	size_t len;

	switch (ADB_VAL_TYPE(v)) {
	case ADB_TYPE_BLOB_8:
		blob = adb_r_deref(db, v, 0, 1);
		len = *(uint8_t*) blob;
		return APK_BLOB_PTR_LEN(adb_r_deref(db, v, 1, len), len);
	case ADB_TYPE_BLOB_16:
		blob = adb_r_deref(db, v, 0, 2);
		len = le16toh(*(uint16_t*) blob);
		return APK_BLOB_PTR_LEN(adb_r_deref(db, v, 2, len), len);
	case ADB_TYPE_BLOB_32:
		blob = adb_r_deref(db, v, 0, 4);
		len = le32toh(*(uint32_t*) blob);
		return APK_BLOB_PTR_LEN(adb_r_deref(db, v, 4, len), len);
	default:
		return APK_BLOB_NULL;
	}
}

struct adb_obj *adb_r_obj(struct adb *db, adb_val_t v, struct adb_obj *obj, const struct adb_object_schema *schema)
{
	adb_val_t *o;
	uint32_t num;

	if (ADB_VAL_TYPE(v) != ADB_TYPE_ARRAY &&
	    ADB_VAL_TYPE(v) != ADB_TYPE_OBJECT)
		goto err;

	o = adb_r_deref(db, v, 0, sizeof(adb_val_t[ADBI_NUM_ENTRIES]));
	if (!o) goto err;

	num = le32toh(o[ADBI_NUM_ENTRIES]);
	o = adb_r_deref(db, v, 0, sizeof(adb_val_t[num]));
	if (!o) goto err;

	*obj = (struct adb_obj) {
		.schema = schema,
		.db = db,
		.num = num,
		.obj = o,
	};
	return obj;
err:
	*obj = (struct adb_obj) {
		.schema = schema,
		.db = db,
		.num = 1,
		.obj = 0,
	};
	return obj;
}

struct adb_obj *adb_r_rootobj(struct adb *db, struct adb_obj *obj, const struct adb_object_schema *schema)
{
	return adb_r_obj(db, adb_r_root(db), obj, schema);
}

adb_val_t adb_ro_val(const struct adb_obj *o, unsigned i)
{
	if (i >= o->num) return ADB_NULL;
	return o->obj[i];
}

uint32_t adb_ro_int(const struct adb_obj *o, unsigned i)
{
	adb_val_t val = adb_ro_val(o, i);
	if (val == ADB_NULL && o->schema && o->schema->get_default_int)
		return o->schema->get_default_int(i);
	return adb_r_int(o->db, val);
}

apk_blob_t adb_ro_blob(const struct adb_obj *o, unsigned i)
{
	return adb_r_blob(o->db, adb_ro_val(o, i));
}

struct adb_obj *adb_ro_obj(const struct adb_obj *o, unsigned i, struct adb_obj *no)
{
	const struct adb_object_schema *schema = NULL;

	if (o->schema) {
		if (o->schema->kind == ADB_KIND_ARRAY)
			schema = container_of(o->schema->fields[0].kind, struct adb_object_schema, kind);
		else if (i > 0 && i < o->schema->num_fields)
			schema = container_of(o->schema->fields[i-1].kind, struct adb_object_schema, kind);
		assert(schema->kind == ADB_KIND_OBJECT || schema->kind == ADB_KIND_ARRAY);
	}

	return adb_r_obj(o->db, adb_ro_val(o, i), no, schema);
}

int adb_ro_cmp(const struct adb_obj *o1, const struct adb_obj *o2, unsigned i)
{
	assert(o1->schema->kind == ADB_KIND_OBJECT);
	assert(o1->schema == o2->schema);
	assert(i > 0 && i < o1->schema->num_fields);

	switch (*o1->schema->fields[i-1].kind) {
	case ADB_KIND_BLOB:
	case ADB_KIND_INT:
		return container_of(o1->schema->fields[i-1].kind, struct adb_scalar_schema, kind)->compare(
			o1->db, adb_ro_val(o1, i),
			o2->db, adb_ro_val(o2, i));
	case ADB_KIND_OBJECT: {
		struct adb_obj so1, so2;
		adb_ro_obj(o1, i, &so1);
		adb_ro_obj(o2, i, &so2);
		return so1.schema->compare(&so1, &so2);
		}
	}
	assert(0);
}

static struct adb *__db1, *__db2;
static const struct adb_object_schema *__schema;

static int wacmp(const void *p1, const void *p2)
{
	struct adb_obj o1, o2;
	adb_r_obj(__db1, *(adb_val_t *)p1, &o1, __schema);
	adb_r_obj(__db2, *(adb_val_t *)p2, &o2, __schema);
	return o1.schema->compare(&o1, &o2);
}

static int wadbcmp(const void *p1, const void *p2)
{
	struct adb a1, a2;
	struct adb_obj o1, o2;
	adb_m_blob(&a1, adb_r_blob(__db1, *(adb_val_t *)p1), 0);
	adb_m_blob(&a2, adb_r_blob(__db2, *(adb_val_t *)p2), 0);
	adb_r_rootobj(&a1, &o1, __schema);
	adb_r_rootobj(&a2, &o2, __schema);
	return __schema->compare(&o1, &o2);
}

int adb_ra_find(struct adb_obj *arr, int cur, struct adb *db, adb_val_t val)
{
	adb_val_t *ndx;

	__db1 = db;
	__db2 = arr->db;
	__schema = arr->schema;
	assert(__schema->kind == ADB_KIND_ARRAY);
	__schema = container_of(__schema->fields[0].kind, struct adb_object_schema, kind);

	if (cur == 0) {
		ndx = bsearch(&val, &arr->obj[ADBI_FIRST], adb_ra_num(arr), sizeof(arr->obj[0]), wacmp);
		if (!ndx) return -1;
		cur = ndx - arr->obj;
		while (cur > 1 && wacmp(&val, &arr->obj[cur-1]) == 0) cur--;
	} else {
		cur++;
		if (wacmp(&val, &arr->obj[cur]) != 0)
			return -1;
	}
	return cur;

}

/* Write interface */
static inline size_t iovec_len(struct iovec *vec, size_t nvec)
{
	size_t i, l = 0;
	for (i = 0; i < nvec; i++) l += vec[i].iov_len;
	return l;
}

static unsigned iovec_hash(struct iovec *vec, size_t nvec, size_t *len)
{
	size_t i, l = 0;
	unsigned hash = 5381;

	for (i = 0; i < nvec; i++) {
		hash = apk_blob_hash_seed(APK_BLOB_PTR_LEN(vec[i].iov_base, vec[i].iov_len), hash);
		l += vec[i].iov_len;
	}
	*len = l;
	return hash;
}

static unsigned iovec_memcmp(struct iovec *vec, size_t nvec, void *base)
{
	uint8_t *b = (uint8_t *) base;
	size_t i;

	for (i = 0; i < nvec; i++) {
		if (memcmp(b, vec[i].iov_base, vec[i].iov_len) != 0)
			return 1;
		b += vec[i].iov_len;
	}
	return 0;
}

static adb_val_t adb_w_error(struct adb *db, int rc)
{
	assert(0);
	db->hdr.magic = 0;
	return ADB_ERROR(rc);
}

static size_t adb_w_raw(struct adb *db, struct iovec *vec, size_t n, size_t len, size_t alignment)
{
	void *ptr;
	size_t offs, i;

	if ((i = ROUND_UP(db->adb.len, alignment) - db->adb.len) != 0) {
		memset(&db->adb.ptr[db->adb.len], 0, i);
		db->adb.len += i;
	}

	if (db->adb.len + len > db->mmap.len) {
		assert(db->num_buckets);
		if (!db->mmap.len) db->mmap.len = 8192;
		while (db->adb.len + len > db->mmap.len)
			db->mmap.len *= 2;
		ptr = realloc(db->adb.ptr, db->mmap.len);
		assert(ptr);
		db->adb.ptr = ptr;
	}

	offs = db->adb.len;
	for (i = 0; i < n; i++) {
		memcpy(&db->adb.ptr[db->adb.len], vec[i].iov_base, vec[i].iov_len);
		db->adb.len += vec[i].iov_len;
	}

	return offs;
}

static size_t adb_w_data(struct adb *db, struct iovec *vec, size_t nvec, size_t alignment)
{
	size_t len, i;
	unsigned hash, bucketno;
	struct adb_w_bucket *bucket;
	struct adb_w_bucket_entry *entry = 0;

	if (!db->num_buckets) return adb_w_raw(db, vec, nvec, iovec_len(vec, nvec), alignment);

	hash = iovec_hash(vec, nvec, &len);
	bucketno = hash % db->num_buckets;
	list_for_each_entry(bucket, &db->bucket[bucketno], node) {
		for (i = 0, entry = bucket->entries; i < ARRAY_SIZE(bucket->entries); i++, entry++) {
			if (entry->len == 0) goto add;
			if (entry->hash != hash) continue;
			if (entry->len == len && iovec_memcmp(vec, nvec, &((uint8_t*)db->adb.ptr)[entry->offs]) == 0) {
				if ((entry->offs & alignment) != 0) goto add;
				return entry->offs;
			}
		}
		entry = 0;
	}

	bucket = calloc(1, sizeof *bucket);
	list_init(&bucket->node);
	list_add_tail(&bucket->node, &db->bucket[bucketno]);
	entry = &bucket->entries[0];

add:
	entry->hash = hash;
	entry->len = len;
	entry->offs = adb_w_raw(db, vec, nvec, len, alignment);
	return entry->offs;
}

static size_t adb_w_data1(struct adb *db, void *ptr, size_t len, size_t alignment)
{
	struct iovec vec[] = {
		{ .iov_base = ptr, .iov_len = len },
	};
	if (!ptr) return ADB_NULL;
	return adb_w_data(db, vec, ARRAY_SIZE(vec), alignment);
}

void adb_w_root(struct adb *db, adb_val_t root_val)
{
	struct iovec vec = {
		.iov_base = &root_val, .iov_len = sizeof(adb_val_t),
	};
	adb_w_raw(db, &vec, 1, vec.iov_len, sizeof root_val);
}

void adb_w_rootobj(struct adb_obj *obj)
{
	adb_w_root(obj->db, adb_w_obj(obj));
}

adb_val_t adb_w_blob(struct adb *db, apk_blob_t b)
{
	union {
		uint32_t u32;
		uint16_t u16;
		uint8_t u8;
	} val;
	uint32_t n = b.len;
	struct iovec vec[2] = {
		{ .iov_base = &val,		.iov_len = sizeof val },
		{ .iov_base = (void *) b.ptr,	.iov_len = n },
	};
	adb_val_t o;

	if (n > 0xffff) {
		val.u32 = htole32(n);
		vec[0].iov_len = sizeof val.u32;
		o = ADB_TYPE_BLOB_32;
	} else if (n > 0xff) {
		val.u16 = htole16(n);
		vec[0].iov_len = sizeof val.u16;
		o = ADB_TYPE_BLOB_16;
	} else {
		val.u8 = n;
		vec[0].iov_len = sizeof val.u8;
		o = ADB_TYPE_BLOB_8;
	}

	return ADB_VAL(o, adb_w_data(db, vec, ARRAY_SIZE(vec), vec[0].iov_len));
}

adb_val_t adb_w_int(struct adb *db, uint32_t val)
{
	if (val >= 0x10000000)
		return ADB_VAL(ADB_TYPE_INT_32, adb_w_data1(db, &val, sizeof val, sizeof val));
	return ADB_VAL(ADB_TYPE_INT, val);
}

adb_val_t adb_w_copy(struct adb *db, struct adb *srcdb, adb_val_t v)
{
	void *ptr;
	size_t sz, align = 1;

	if (db == srcdb) return v;

	switch (ADB_VAL_TYPE(v)) {
	case ADB_TYPE_SPECIAL:
	case ADB_TYPE_INT:
		return v;
	case ADB_TYPE_INT_32:
		sz = align = sizeof(uint32_t);
		goto copy;
	case ADB_TYPE_BLOB_8:
		ptr = adb_r_deref(srcdb, v, 0, 1);
		sz = 1UL + *(uint8_t*) ptr;
		goto copy;
	case ADB_TYPE_BLOB_16:
		ptr = adb_r_deref(srcdb, v, 0, 2);
		sz = 1UL + *(uint16_t*) ptr;
		goto copy;
	case ADB_TYPE_OBJECT:
	case ADB_TYPE_ARRAY: {
		adb_val_t cpy[512];
		struct adb_obj obj;
		adb_r_obj(srcdb, v, &obj, NULL);
		sz = adb_ro_num(&obj);
		if (sz > ARRAY_SIZE(cpy)) return adb_w_error(db, E2BIG);
		cpy[ADBI_NUM_ENTRIES] = obj.obj[ADBI_NUM_ENTRIES];
		for (int i = ADBI_FIRST; i < sz; i++) cpy[i] = adb_w_copy(db, srcdb, adb_ro_val(&obj, i));
		return ADB_VAL(ADB_VAL_TYPE(v), adb_w_data1(db, cpy, sizeof(adb_val_t[sz]), sizeof(adb_val_t)));
	}
	case ADB_TYPE_INT_64:
	case ADB_TYPE_BLOB_32:
	default:
		return adb_w_error(db, ENOSYS);
	}
copy:
	ptr = adb_r_deref(srcdb, v, 0, sz);
	return ADB_VAL(ADB_VAL_TYPE(v), adb_w_data1(db, ptr, sz, align));
}

adb_val_t adb_w_adb(struct adb *db, struct adb *valdb)
{
	uint32_t bsz;
	struct adb_block blk = {
		.type_size = htole32((ADB_BLOCK_ADB << 30) + valdb->adb.len)
	};
	struct iovec vec[] = {
		{ .iov_base = &bsz, .iov_len = sizeof bsz },
		{ .iov_base = &blk, .iov_len = sizeof blk },
		{ .iov_base = valdb->adb.ptr, .iov_len = valdb->adb.len },
	};
	if (valdb->adb.len <= 4) return ADB_NULL;
	bsz = htole32(iovec_len(vec, ARRAY_SIZE(vec)) - sizeof bsz);
	return ADB_VAL(ADB_TYPE_BLOB_32, adb_w_raw(db, vec, ARRAY_SIZE(vec), iovec_len(vec, ARRAY_SIZE(vec)), sizeof(uint32_t)));
}

adb_val_t adb_w_fromstring(struct adb *db, const uint8_t *kind, apk_blob_t val)
{
	int r;

	switch (*kind) {
	case ADB_KIND_BLOB:
	case ADB_KIND_INT:
		return container_of(kind, struct adb_scalar_schema, kind)->fromstring(db, val);
	case ADB_KIND_OBJECT:
	case ADB_KIND_ARRAY:; {
		struct adb_obj obj;
		struct adb_object_schema *schema = container_of(kind, struct adb_object_schema, kind);
		adb_wo_alloca(&obj, schema, db);
		r = schema->fromstring(&obj, val);
		if (r) return ADB_ERROR(r);
		return adb_w_obj(&obj);
		}
	default:
		return ADB_ERROR(ENOSYS);
	}
}

struct adb_obj *adb_wo_init(struct adb_obj *o, adb_val_t *p, const struct adb_object_schema *schema, struct adb *db)
{
	memset(p, 0, sizeof(adb_val_t[schema->num_fields]));
	/* Use the backing num entries index as the 'maximum' allocated space
	 * information while building the object/array. */
	p[ADBI_NUM_ENTRIES] = schema->num_fields;

	*o = (struct adb_obj) {
		.schema = schema,
		.db = db,
		.obj = p,
		.num = 1,
	};
	return o;
}

void adb_wo_reset(struct adb_obj *o)
{
	uint32_t max = o->obj[ADBI_NUM_ENTRIES];
	memset(o->obj, 0, sizeof(adb_val_t[o->num]));
	o->obj[ADBI_NUM_ENTRIES] = max;
	o->num = 1;
}

void adb_wo_resetdb(struct adb_obj *o)
{
	adb_wo_reset(o);
	adb_reset(o->db);
}

static adb_val_t __adb_w_obj(struct adb_obj *o, uint32_t type)
{
	uint32_t n, max = o->obj[ADBI_NUM_ENTRIES];
	adb_val_t *obj = o->obj, val = ADB_NULL;

	if (o->schema && o->schema->pre_commit) o->schema->pre_commit(o);

	for (n = o->num; n > 1 && obj[n-1] == ADB_NULL; n--)
		;
	if (n > 1) {
		obj[ADBI_NUM_ENTRIES] = htole32(n);
		val = ADB_VAL(type, adb_w_data1(o->db, obj, sizeof(adb_val_t[n]), sizeof(adb_val_t)));
	}
	adb_wo_reset(o);
	o->obj[ADBI_NUM_ENTRIES] = max;
	return val;
}

adb_val_t adb_w_obj(struct adb_obj *o)
{
	return __adb_w_obj(o, ADB_TYPE_OBJECT);
}

adb_val_t adb_w_arr(struct adb_obj *o)
{
	return __adb_w_obj(o, ADB_TYPE_ARRAY);
}

adb_val_t adb_wo_fromstring(struct adb_obj *o, apk_blob_t val)
{
	adb_wo_reset(o);
	return o->schema->fromstring(o, val);
}

adb_val_t adb_wo_val(struct adb_obj *o, unsigned i, adb_val_t v)
{
	if (i >= o->obj[ADBI_NUM_ENTRIES]) return adb_w_error(o->db, E2BIG);
	if (ADB_IS_ERROR(v)) return adb_w_error(o->db, ADB_VAL_VALUE(v));
	if (v != ADB_NULL && i >= o->num) o->num = i + 1;
	return o->obj[i] = v;
}

adb_val_t adb_wo_val_fromstring(struct adb_obj *o, unsigned i, apk_blob_t val)
{
	if (i >= o->obj[ADBI_NUM_ENTRIES]) return adb_w_error(o->db, E2BIG);
	if (i >= o->num) o->num = i + 1;
	return o->obj[i] = adb_w_fromstring(o->db, o->schema->fields[i-1].kind, val);
}

adb_val_t adb_wo_int(struct adb_obj *o, unsigned i, uint32_t v)
{
	if (o->schema && o->schema->get_default_int &&
	    v == o->schema->get_default_int(i))
		return ADB_NULL;
	return adb_wo_val(o, i, adb_w_int(o->db, v));
}

adb_val_t adb_wo_blob(struct adb_obj *o, unsigned i, apk_blob_t b)
{
	assert(o->schema->kind == ADB_KIND_OBJECT);
	return adb_wo_val(o, i, adb_w_blob(o->db, b));
}

adb_val_t adb_wo_obj(struct adb_obj *o, unsigned i, struct adb_obj *no)
{
	assert(o->schema->kind == ADB_KIND_OBJECT);
	assert(o->db == no->db);
	return adb_wo_val(o, i, adb_w_obj(no));
}

adb_val_t adb_wo_arr(struct adb_obj *o, unsigned i, struct adb_obj *no)
{
	assert(o->schema->kind == ADB_KIND_OBJECT || o->schema->kind == ADB_KIND_ARRAY);
	assert(o->db == no->db);
	return adb_wo_val(o, i, adb_w_arr(no));
}

adb_val_t adb_wa_append(struct adb_obj *o, adb_val_t v)
{
	assert(o->schema->kind == ADB_KIND_ARRAY);
	if (o->num >= o->obj[ADBI_NUM_ENTRIES]) return adb_w_error(o->db, E2BIG);
	if (ADB_IS_ERROR(v)) return adb_w_error(o->db, ADB_VAL_VALUE(v));
	o->obj[o->num++] = v;
	return v;
}

adb_val_t adb_wa_append_obj(struct adb_obj *o, struct adb_obj *no)
{
	assert(o->schema->kind == ADB_KIND_ARRAY);
	assert(o->db == no->db);
	return adb_wa_append(o, adb_w_obj(no));
}

adb_val_t adb_wa_append_fromstring(struct adb_obj *o, apk_blob_t b)
{
	assert(o->schema->kind == ADB_KIND_ARRAY);
	return adb_wa_append(o, adb_w_fromstring(o->db, o->schema->fields[0].kind, b));
}

void adb_wa_sort(struct adb_obj *arr)
{
	assert(arr->schema->kind == ADB_KIND_ARRAY);
	__db1 = __db2 = arr->db;
	switch (*arr->schema->fields[0].kind) {
	case ADB_KIND_OBJECT:
		__schema = container_of(arr->schema->fields[0].kind, struct adb_object_schema, kind);
		qsort(&arr->obj[ADBI_FIRST], adb_ra_num(arr), sizeof(arr->obj[0]), wacmp);
		break;
	case ADB_KIND_ADB:
		__schema = container_of(arr->schema->fields[0].kind, struct adb_adb_schema, kind)->schema;
		qsort(&arr->obj[ADBI_FIRST], adb_ra_num(arr), sizeof(arr->obj[0]), wadbcmp);
		break;
	default:
		assert(1);
	}
}

void adb_wa_sort_unique(struct adb_obj *arr)
{
	int i, j, num;

	adb_wa_sort(arr);
	num = adb_ra_num(arr);
	if (num >= 2) {
		for (i = 2, j = 2; i <= num; i++) {
			if (arr->obj[i] == arr->obj[i-1]) continue;
			arr->obj[j++] = arr->obj[i];
		}
		arr->num = j;
	}
}

/* Schema helpers */
int adb_s_field_by_name(const struct adb_object_schema *schema, const char *name)
{
	for (int i = 0; i < schema->num_fields; i++)
		if (strcmp(schema->fields[i].name, name) == 0)
			return i + 1;
	return 0;
}

/* Container creation */
int adb_c_header(struct apk_ostream *os, struct adb *db)
{
	return apk_ostream_write(os, &db->hdr, sizeof db->hdr);
}

int adb_c_block(struct apk_ostream *os, uint32_t type, apk_blob_t val)
{
	struct adb_block blk = {
		.type_size = htole32((type << 30) + val.len)
	};
	int r;

	r = apk_ostream_write(os, &blk, sizeof blk);
	if (r < 0) return r;

	r = apk_ostream_write(os, val.ptr, val.len);
	if (r < 0) return r;
	return 0;
}

int adb_c_block_copy(struct apk_ostream *os, struct adb_block *b, struct apk_istream *is, struct adb_verify_ctx *vfy)
{
	EVP_MD_CTX *mdctx = NULL;
	int r;

	r = apk_ostream_write(os, b, sizeof *b);
	if (r < 0) return r;

	if (vfy) {
		mdctx = EVP_MD_CTX_new();
		EVP_DigestInit_ex(mdctx, EVP_sha512(), 0);
	}
	r = apk_stream_copy(is, os, ADB_BLOCK_SIZE(b), 0, 0, mdctx);
	if (vfy) {
		EVP_DigestFinal_ex(mdctx, vfy->sha512, 0);
		EVP_MD_CTX_free(mdctx);
		vfy->calc |= (1 << ADB_HASH_SHA512);
	}
	return r;
}

int adb_c_create(struct apk_ostream *os, struct adb *db, struct adb_trust *t)
{
	if (IS_ERR(os)) return PTR_ERR(os);
	if (db->hdr.magic != htole32(ADB_FORMAT_MAGIC)) {
		apk_ostream_cancel(os, -EAPKFORMAT);
		goto ret;
	}
	adb_c_header(os, db);
	adb_c_block(os, ADB_BLOCK_ADB, db->adb);
	if (t) adb_trust_write_signatures(t, db, NULL, os);
ret:
	return apk_ostream_close(os);
}

/* Container transformation interface */
int adb_c_xfrm(struct adb_xfrm *x, int (*cb)(struct adb_xfrm *, struct adb_block *, struct apk_istream *))
{
	struct adb_block blk;
	struct apk_segment_istream seg;
	int r, block_no = 0;
	size_t sz;

	r = apk_istream_read(x->is, &x->db.hdr, sizeof x->db.hdr);
	if (r < 0) goto err;

	if (x->db.hdr.magic != htole32(ADB_FORMAT_MAGIC)) goto bad_msg;
	r = apk_ostream_write(x->os, &x->db.hdr, sizeof x->db.hdr);
	if (r < 0) goto err;

	do {
		r = apk_istream_read(x->is, &blk, sizeof blk);
		if (r <= 0) {
			if (r == 0) r = cb(x, NULL, NULL);
			goto err;
		}

		if ((block_no++ == 0) != (ADB_BLOCK_TYPE(&blk) == ADB_BLOCK_ADB)) goto bad_msg;

		sz = ADB_BLOCK_SIZE(&blk);
		r = cb(x, &blk, apk_istream_segment(&seg, x->is, sz, 0));
		if (r < 0) goto err;

		if (r == 0 && seg.bytes_left == sz) {
			r = apk_ostream_write(x->os, &blk, sizeof blk);
			if (r < 0) goto err;
			r = apk_stream_copy(x->is, x->os, seg.bytes_left, 0, 0, 0);
			if (r < 0) goto err;
		} else if (seg.bytes_left > 0) {
			r = apk_istream_read(x->is, NULL, sz - seg.bytes_left);
			if (r < 0) goto err;
		}
	} while (1);
bad_msg:
	r = -EBADMSG;
err:
	apk_ostream_cancel(x->os, r);
	return r;
}
